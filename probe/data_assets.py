"""Bounded local data-asset discovery executed on the probe host.

The probe walks the directories an administrator configured (plus optional
local database service detection) and reports *what data exists on that
server* to the platform: file identity, size, inferred columns and the
sensitive-data categories found inside each file.

Only aggregate evidence leaves the host - category counts, column names and
matched-value counts. Raw file content and matched values are never uploaded,
so the inventory can run on production servers without exfiltrating data.
"""
from __future__ import annotations

import csv
import gzip
import stat as stat_module
import hashlib
import io
import json
import re
import socket
import time
from datetime import UTC, datetime
from pathlib import Path

HASH_LIMIT = 8 * 1024 * 1024
SCAN_LIMIT = 2 * 1024 * 1024
SAMPLE_ROWS = 25
MAX_DIRECTORIES = 500

TEXT_EXTENSIONS = {
    '.csv', '.tsv', '.txt', '.log', '.sql', '.json', '.jsonl', '.xml', '.yaml', '.yml',
    '.ini', '.conf', '.cfg', '.env', '.md', '.rst', '.properties',
}
TABLE_EXTENSIONS = {'.csv', '.tsv', '.sql', '.json', '.jsonl', '.xlsx', '.xlsm'}
DATABASE_EXTENSIONS = {'.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.dump', '.bak', '.sql.gz'}
SKIP_DIRECTORIES = {
    'proc', 'sys', 'dev', 'run', 'node_modules', '__pycache__', '.git', '.svn', '.cache',
    '.venv', 'venv', 'site-packages', 'lost+found', 'snap', '.tox', '.mypy_cache',
}
SENSITIVE_RULES = {
    'phone': re.compile(r'(?<!\d)1[3-9]\d{9}(?!\d)'),
    'id_card': re.compile(r'(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)'),
    'bank_card': re.compile(r'(?<!\d)(?:62|4\d{3}|5[1-5]\d{2})[ -]?(?:\d[ -]?){12,17}(?!\d)'),
    'email': re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    'api_key': re.compile(r'\b(?:AKIA|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{20,})\b'),
    'token': re.compile(r'\b(?:Bearer\s+)?[A-Za-z0-9_\-]{32,}\b'),
}
COLUMN_HINTS = {
    'phone': ('phone', 'mobile', 'cellphone', '手机', '联系电话', 'tel'),
    'id_card': ('id_card', 'idcard', 'identity', '身份证', '证件'),
    'bank_card': ('bank_card', 'card_no', 'cardno', '账号', '银行卡'),
    'email': ('email', 'mail', '邮箱'),
    'name': ('name', '姓名', 'fullname'),
    'address': ('address', 'addr', '地址', '住址'),
    'user_id': ('user_id', 'userid', 'uid', '账号', 'account'),
    'medical_record': ('medical', 'patient', 'diagnosis', '病历', '诊断'),
    'credential': ('password', 'passwd', 'secret', 'token', '密钥', '口令'),
}
SEVERITY_BY_CATEGORY = {
    'api_key': 'Critical', 'token': 'Critical', 'credential': 'Critical',
    'id_card': 'High', 'bank_card': 'High', 'medical_record': 'High',
    'phone': 'Medium', 'email': 'Medium', 'address': 'Medium',
    'name': 'Low', 'user_id': 'Low',
}
LOCAL_DATABASE_SERVICES = {3306: 'mysql', 5432: 'postgresql', 6379: 'redis', 27017: 'mongodb',
                           1433: 'mssql', 1521: 'oracle', 9200: 'elasticsearch', 5984: 'couchdb'}


def _severity(categories: list[str]) -> str:
    ranked = [SEVERITY_BY_CATEGORY.get(item, 'Low') for item in categories]
    for level in ('Critical', 'High', 'Medium', 'Low'):
        if level in ranked:
            return level
    return 'Low'


def scan_text(text: str, limit: int = SCAN_LIMIT) -> dict[str, int]:
    sample = text[:limit]
    return {name: len(pattern.findall(sample)) for name, pattern in SENSITIVE_RULES.items()}


def _csv_columns(text: str, delimiter: str = ',') -> list[dict]:
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    try:
        header = next(reader)
    except (StopIteration, csv.Error):
        return []
    rows: list[list[str]] = []
    for _ in range(SAMPLE_ROWS):
        try:
            rows.append(next(reader))
        except (StopIteration, csv.Error):
            break
    columns = []
    for index, name in enumerate(header[:64]):
        cells = [row[index] for row in rows if index < len(row)]
        joined = ' '.join(cells)[:4096]
        counts = {category: len(pattern.findall(joined)) for category, pattern in SENSITIVE_RULES.items()}
        categories = [category for category, count in counts.items() if count]
        hint_categories = [category for category, words in COLUMN_HINTS.items() if any(word in name.lower() for word in words)]
        for category in hint_categories:
            if category not in categories and category in SEVERITY_BY_CATEGORY:
                categories.append(category)
        detected_type = categories[0] if categories else 'text'
        columns.append({
            'name': str(name)[:256] or f'column_{index + 1}',
            'detected_type': detected_type,
            'sensitivity': _severity(categories) if categories else 'Unknown',
            'confidence': 0.9 if counts.get(detected_type) else (0.6 if categories else 0.3),
            'categories': categories,
            'count': sum(counts.values()),
        })
    return columns


def _sql_columns(text: str) -> list[dict]:
    names: list[str] = []
    for block in re.findall(r'\b(?:CREATE|INSERT INTO)\b[^(]*\(([^)]*)\)', text[:200000], re.IGNORECASE):
        for item in block.split(','):
            token = item.strip().split()[0] if item.strip() else ''
            token = token.strip('`"[]')
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', token or '') and token not in names:
                names.append(token)
    columns = []
    for name in names[:64]:
        categories = [category for category, words in COLUMN_HINTS.items() if any(word in name.lower() for word in words)]
        columns.append({
            'name': name,
            'detected_type': categories[0] if categories else 'text',
            'sensitivity': _severity(categories) if categories else 'Unknown',
            'confidence': 0.6 if categories else 0.3,
            'categories': categories,
            'count': 0,
        })
    return columns


def _json_columns(text: str, jsonl: bool = False) -> list[dict]:
    try:
        data = [json.loads(line) for line in text.splitlines()[:SAMPLE_ROWS] if line.strip()] if jsonl else json.loads(text[:SCAN_LIMIT])
    except (ValueError, TypeError):
        return []
    if isinstance(data, dict):
        names = list(data.keys())[:64]
    elif isinstance(data, list) and data and isinstance(data[0], dict):
        names = list(dict.fromkeys(key for row in data[:SAMPLE_ROWS] if isinstance(row, dict) for key in row))[:64]
    else:
        return []
    columns = []
    for name in names:
        records = [data] if isinstance(data, dict) else data[:SAMPLE_ROWS]
        sample = ' '.join(str(row.get(name, ''))[:4096] for row in records if isinstance(row, dict))[:4096]
        counts = scan_text(sample)
        categories = [category for category, words in COLUMN_HINTS.items() if any(word in str(name).lower() for word in words)]
        categories = list(dict.fromkeys([*categories, *(category for category, count in counts.items() if count)]))
        columns.append({
            'name': str(name)[:256] or 'unnamed',
            'detected_type': categories[0] if categories else 'text',
            'sensitivity': _severity(categories) if categories else 'Unknown',
            'confidence': 0.9 if any(counts.values()) else (0.6 if categories else 0.3),
            'categories': categories,
            'count': sum(counts.values()),
        })
    return columns


def infer_columns(text: str, suffix: str) -> list[dict]:
    if suffix in {'.csv', '.tsv'}:
        return _csv_columns(text, '\t' if suffix == '.tsv' else ',')
    if suffix == '.sql':
        return _sql_columns(text)
    if suffix in {'.json', '.jsonl'}:
        return _json_columns(text, suffix == '.jsonl')
    return []


def _read_text(path: Path) -> str:
    opener = gzip.open if path.name.lower().endswith('.sql.gz') else open
    with opener(path, 'rb') as handle:
        raw = handle.read(SCAN_LIMIT)
    for encoding in ('utf-8-sig', 'gb18030'):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode('utf-8', errors='replace')


def _sha256(path: Path, size: int) -> str:
    if size > HASH_LIMIT:
        return ''
    digest = hashlib.sha256()
    try:
        with path.open('rb') as handle:
            remaining = HASH_LIMIT + 1
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            if remaining == 0:
                return ''
    except OSError:
        return ''
    return digest.hexdigest()


def inspect_file(path: Path) -> dict | None:
    try:
        stat = path.lstat()
    except OSError:
        return None
    if not stat_module.S_ISREG(stat.st_mode):
        return None
    suffix = path.suffix.lower()
    lower_name = path.name.lower()
    if lower_name.endswith('.sql.gz'):
        suffix = '.sql'
    if lower_name == '.env':
        suffix = '.env'
    read_error = ''
    try:
        text = _read_text(path) if suffix in TEXT_EXTENSIONS else ''
    except (OSError, EOFError) as exc:
        text = ''
        read_error = type(exc).__name__
    counts = scan_text(text) if text else {}
    categories = [category for category, count in counts.items() if count]
    columns = infer_columns(text, suffix)
    for column in columns:
        for category in column['categories']:
            if category not in categories:
                categories.append(category)
    if suffix in DATABASE_EXTENSIONS or suffix == '.sql':
        asset_type, sensitivity = 'database', _severity(categories) if categories else 'Medium'
        categories = categories or ['database']
    elif suffix in TABLE_EXTENSIONS:
        asset_type, sensitivity = 'table', _severity(categories)
    else:
        asset_type, sensitivity = 'file', _severity(categories)
    if not text and not categories:
        sensitivity = 'Low'
    return {
        'name': str(path.name)[:512],
        'asset_type': asset_type,
        'sensitivity': sensitivity,
        'path': str(path)[:1024],
        'size': int(stat.st_size),
        'sha256': _sha256(path, int(stat.st_size)),
        'modified_at': datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
        'categories': categories[:16],
        'counts': counts,
        'columns': columns[:256],
        'evidence': {'extension': suffix, 'scanned_bytes': len(text), 'sample_rows': SAMPLE_ROWS, 'sampled': stat.st_size > SCAN_LIMIT, 'read_error': read_error},
    }


def _directory_asset(path: Path, file_count: int, total_size: int, categories: list[str]) -> dict:
    return {
        'name': str(path.name or path)[:512],
        'asset_type': 'directory',
        'sensitivity': _severity(categories),
        'path': str(path)[:1024],
        'size': int(total_size),
        'sha256': '',
        'modified_at': '',
        'categories': categories[:16],
        'counts': {},
        'columns': [],
        'evidence': {'file_count': file_count},
    }


def _category_hints(path: Path) -> list[str]:
    name = str(path).lower()
    return [category for category, words in COLUMN_HINTS.items() if any(word in name for word in words)]


def detect_local_databases(ports: dict[int, str], timeout: float = 0.4) -> list[dict]:
    found: list[dict] = []
    for port, engine in sorted(ports.items()):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=timeout):
                pass
        except OSError:
            continue
        found.append({
            'name': f'{engine}@127.0.0.1:{port}',
            'asset_type': 'database',
            'sensitivity': 'Medium',
            'path': f'127.0.0.1:{port}',
            'size': 0,
            'sha256': '',
            'modified_at': '',
            'categories': ['database', engine],
            'counts': {},
            'columns': [],
            'evidence': {'engine': engine, 'port': port, 'listening': True},
        })
    return found


def discover_data_assets(config: dict, stop_event=None) -> dict:
    """Walk configured paths and return a bounded data-asset inventory."""
    started = time.monotonic()
    paths = [Path(str(item)).expanduser() for item in (config.get('paths') or []) if str(item).strip()]
    configured = bool(paths)
    max_files = min(max(int(config.get('max_files', 200)), 1), 2000)
    max_depth = min(max(int(config.get('max_depth', 3)), 0), 8)
    deadline = started + min(max(int(config.get('timeout_seconds', 120)), 5), 1800)
    include_databases = bool(config.get('include_databases', True))
    assets: list[dict] = []
    scanned_paths: list[str] = []
    directories = 0
    file_count = 0
    visited = set()
    truncated = False
    errors = []

    def expired() -> bool:
        return time.monotonic() >= deadline or bool(stop_event and stop_event.is_set())

    def walk_error(exc):
        if len(errors) < 10:
            errors.append(f'目录不可读取: {exc.filename}')

    for root in paths:
        if expired():
            truncated = True
            break
        if root.is_symlink() or not root.is_dir():
            errors.append(f'目录不存在或不可读取: {root}')
            continue
        root = root.absolute()
        scanned_paths.append(str(root))
        for current, subdirs, files in _walk(root, max_depth, walk_error):
            if expired() or directories >= MAX_DIRECTORIES:
                truncated = True
                break
            directories += 1
            subdirs[:] = sorted(item for item in subdirs if item not in SKIP_DIRECTORIES and not item.startswith('.docker'))
            total_size = 0
            counted = 0
            directory_categories = set()
            for name in sorted(files):
                path = Path(current) / name
                if path in visited or path.is_symlink():
                    continue
                if expired() or file_count >= max_files:
                    truncated = True
                    break
                visited.add(path)
                record = inspect_file(path)
                if not record:
                    continue
                if record['evidence'].get('read_error'):
                    errors.append(f'文件不可读取: {path}')
                total_size += record['size']
                counted += 1
                file_count += 1
                directory_categories.update(record['categories'])
                assets.append(record)
            if counted:
                assets.append(_directory_asset(Path(current), counted, total_size, sorted(directory_categories)))
            if truncated:
                break
        if truncated:
            break
    databases = []
    if include_databases:
        for port, engine in LOCAL_DATABASE_SERVICES.items():
            if expired():
                truncated = True
                break
            databases.extend(detect_local_databases({port: engine}, timeout=min(.4, max(.01, deadline - time.monotonic()))))
    truncated = truncated or expired()
    error = '; '.join(errors)[:500] if configured else '未配置数据资产采集目录（agent.paths / data.paths）'
    counts: dict[str, int] = {}
    for item in assets:
        for category in item.get('categories', []):
            counts[category] = counts.get(category, 0) + 1
    return {
        'assets': assets,
        'databases': databases,
        'scanned_paths': scanned_paths,
        'counts': counts,
        'max_depth': max_depth,
        'complete': bool(scanned_paths) and not truncated and not errors,
        'error': error,
        'observed_at': datetime.now(UTC).isoformat(),
        'scanner': 'probe-file-inventory',
        'location': 'probe',
        'duration_ms': int((time.monotonic() - started) * 1000),
    }


def _walk(root: Path, max_depth: int, onerror=None):
    """os.walk wrapper honouring the depth limit without loading the whole tree."""
    import os

    base_depth = len(root.parts)
    for current, subdirs, files in os.walk(root, followlinks=False, onerror=onerror):
        depth = len(Path(current).parts) - base_depth
        if depth >= max_depth:
            subdirs[:] = []
        yield current, subdirs, files
