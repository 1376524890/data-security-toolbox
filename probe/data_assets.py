"""Bounded local data-asset discovery executed on the probe host.

The probe walks the directories an administrator configured (plus optional
local database service detection) and reports *what data exists on that
server* to the platform: file identity, size, inferred columns and the
sensitive-data categories found inside each file.

Detection itself is delegated to the shared engine
(``shared/sensitive_detection``) so the probe, the platform file engine and the
network DLP text stage classify a value identically. Only aggregate evidence
leaves the host - category counts, column names and hit counts. Raw file content
and matched values are never uploaded and are never put into the report.
"""
from __future__ import annotations

import os
import socket
import stat as stat_module
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# The probe is installed as <app>/probe/probe.py with the shared package in
# <app>/shared/, and a source checkout has the same relative layout, so the
# parent directory resolves in both places.
_APP_ROOT = Path(__file__).resolve().parent.parent
if (_APP_ROOT / "shared" / "sensitive_detection").is_dir() and str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))

from shared.sensitive_detection import (  # noqa: E402
    SensitiveDetectionContext,
    build_engine,
    canonical_entity,
    legacy_name,
    level_of,
    severity_of,
)
from shared.sensitive_detection.report_guard import sanitize_report  # noqa: E402
from shared.scanning import magic as magic_module  # noqa: E402
from shared.scanning.budget import (  # noqa: E402
    DEFAULT_LIMITS,
    TERMINATION_COMPLETE,
    TERMINATION_UNCONFIGURED,
    TERMINATION_UNREADABLE,
    BudgetExceeded,
    ScanBudget,
)

#: Single source of truth for the documented defaults lives in the shared budget.
DEFAULT_LIMITS_FALLBACK = DEFAULT_LIMITS
from shared.scanning.cache import AnalysisCache, config_fingerprint, key_for  # noqa: E402
from shared.scanning.fingerprint import identify as identify_file  # noqa: E402
from shared.scanning.parsers import parse_file  # noqa: E402

#: Report schema this probe writes. A server that sees no ``schema_version``
#: treats the payload as the legacy 1.0 shape instead of guessing.
REPORT_SCHEMA_VERSION = '1.1'
#: Aggregated progress is pushed at most this often - never per file, and never
#: so rarely that a long scan looks frozen.
PROGRESS_INTERVAL_SECONDS = 5.0

# Kept for compatibility with the previous release: these were the fixed limits
# and now supply the defaults of the versioned ScanProfile.
HASH_LIMIT = 8 * 1024 * 1024
SCAN_LIMIT = 2 * 1024 * 1024
SAMPLE_ROWS = 25
MAX_DIRECTORIES = 500

# A category has to clear this confidence before it can make a whole file look
# sensitive. Context words such as "病历" keep their own (low) confidence and stay
# in the per-file evidence without upgrading the file.
CATEGORY_MIN_CONFIDENCE = 0.5

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
LOCAL_DATABASE_SERVICES = {3306: 'mysql', 5432: 'postgresql', 6379: 'redis', 27017: 'mongodb',
                           1433: 'mssql', 1521: 'oracle', 9200: 'elasticsearch', 5984: 'couchdb'}
SEVERITY_ORDER = ('Critical', 'High', 'Medium', 'Low')


def _normalise_scope_path(value) -> str:
    """Compare scope paths with one separator, whatever host we run on.

    A bare name keeps its meaning: only a real path separator turns an entry into
    a subtree prefix, so a Windows drive path and a Linux absolute path behave the
    same way instead of one of them silently never matching.
    """
    text = str(value or '').strip()
    if os.sep != '/':
        text = text.replace(os.sep, '/')
    return text.rstrip('/')


class ScopeFilter:
    """The configured exclusions and file-type allow-list for one scan.

    Two kinds of exclusion are supported because they answer different questions:
    a bare name (``node_modules``) filters that directory wherever it appears, and
    an absolute path excludes exactly one subtree. Path matching happens on whole
    path segments, so excluding ``/srv/data/tmp`` never silently excludes
    ``/srv/data/tmp-backup``. What was filtered is reported back as counts, because
    a scan that filtered everything must not look like a scan that found nothing.
    """

    __slots__ = ('names', 'prefixes', 'extensions', 'files_excluded',
                 'directories_excluded', 'files_filtered')

    __slots__ = ('names', 'prefixes', 'extensions', 'files_excluded',
                 'directories_excluded', 'files_filtered')

    def __init__(self, exclude_paths=None, file_types=None) -> None:
        names: set[str] = set()
        prefixes: list[str] = []
        for raw in exclude_paths or []:
            value = _normalise_scope_path(raw)
            if not value:
                continue
            if value.startswith('/') or '/' in value:
                prefixes.append(value)
            else:
                names.add(value)
        extensions: set[str] = set()
        for raw in file_types or []:
            value = str(raw).strip().lower()
            if not value:
                continue
            extensions.add(value if value.startswith('.') else '.' + value)
        self.names = frozenset(names)
        # Longest first, so the most specific exclusion is described first.
        self.prefixes = tuple(sorted(set(prefixes), key=len, reverse=True))
        self.extensions = frozenset(extensions)
        self.files_excluded = 0
        self.directories_excluded = 0
        self.files_filtered = 0

    @property
    def active(self) -> bool:
        return bool(self.names or self.prefixes or self.extensions)

    def excludes_directory(self, name: str, path: str) -> bool:
        return name in self.names or self.excludes_path(path)

    def excludes_path(self, path: str) -> bool:
        candidate = _normalise_scope_path(path)
        for prefix in self.prefixes:
            if candidate == prefix or candidate.startswith(prefix + '/'):
                return True
        return False

    def allows_file(self, name: str) -> bool:
        """An empty allow-list means every type is in scope."""
        if not self.extensions:
            return True
        suffix = name[name.rfind('.'):].lower() if '.' in name else ''
        return suffix in self.extensions

    def note_directory(self) -> None:
        self.directories_excluded += 1

    def note_excluded_file(self) -> None:
        self.files_excluded += 1

    def note_filtered_file(self) -> None:
        self.files_filtered += 1

    def evidence(self, exclude_paths=None, file_types=None) -> dict:
        return {'exclude_paths': list(exclude_paths or []),
                'file_types': list(file_types or []),
                'excluded_files': self.files_excluded,
                'excluded_directories': self.directories_excluded,
                'files_filtered_by_type': self.files_filtered}


def scope_filter_for(config: dict) -> ScopeFilter:
    """Build the filter a scan config asks for; an absent config filters nothing."""
    raw_excludes = config.get('exclude_paths')
    if isinstance(raw_excludes, str):
        raw_excludes = [raw_excludes]
    elif not isinstance(raw_excludes, (list, tuple)):
        raw_excludes = []
    raw_types = config.get('file_types')
    if isinstance(raw_types, str):
        raw_types = [item for item in raw_types.replace(',', ' ').split() if item]
    elif not isinstance(raw_types, (list, tuple)):
        raw_types = []
    return ScopeFilter(raw_excludes, raw_types)

_ENGINE = None


def use_engine(candidate) -> None:
    """Pin the detection engine used by subsequent scans.

    ``probe.py`` installs the engine loaded from the active rule pack before a
    scan task starts, so one task is analysed with exactly one rule version and a
    hot update applies to the next task. ``None`` restores the in-package rules.
    """
    global _ENGINE
    _ENGINE = candidate if candidate is not None else build_engine()


def engine():
    """The shared detection engine, built once per process."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = build_engine()
    return _ENGINE


def legacy_categories() -> tuple[str, ...]:
    names = [legacy_name(rule.get('entity')) for rule in engine().rules]
    return tuple(dict.fromkeys(name for name in names if name))


def category_level(category: str) -> str:
    """``L1``..``L4`` for a known data category, ``""`` when it is not personal data."""
    canonical = canonical_entity(category)
    return level_of(canonical) if legacy_name(canonical) else ''


def category_severity(category: str) -> str:
    """Legacy Critical/High/Medium/Low for a category; unknown ones stay Low."""
    canonical = canonical_entity(category)
    return severity_of(canonical) if legacy_name(canonical) else 'Low'


def _severity(categories: list[str]) -> str:
    ranked = [category_severity(item) for item in categories]
    for level in SEVERITY_ORDER:
        if level in ranked:
            return level
    return 'Low'


def scan_text(text: str, limit: int = SCAN_LIMIT) -> dict[str, int]:
    """Per-category hit counts for a block of text. No matched value is returned."""
    counts: dict[str, int] = {name: 0 for name in legacy_categories()}
    for hit in engine().scan_text(text[:limit], source_type='file'):
        if not hit.count:
            continue
        category = legacy_name(hit.entity) or hit.entity.lower()
        counts[category] = counts.get(category, 0) + hit.count
    return counts


def _hit_summary(hits, *, field_name: str = '', sheet_name: str = '',
                  column_index: int | None = None) -> list[dict]:
    """Explain a hit: rule, type, count, confidence and the matched原文.

    The per-rule ``evidence`` entries come from the shared engine, whose
    ``Evidence`` structure has no field for a matched value; they are what lets
    the platform build one Detection with several de-duplicated Evidence rows
    instead of a single unexplainable count. The value itself travels in
    ``matches`` (engine-capped: a few strings, each length-limited), because the
    operator asked to see what was found; a hit that only matched a field name
    has no value and therefore reports none.
    """
    summary = []
    for hit in hits:
        if not hit.sensitive:
            continue
        item = {
            'entity': hit.entity,
            'category': legacy_name(hit.entity) or hit.entity.lower(),
            'count': hit.count,
            'confidence': hit.confidence,
            'confirmed': hit.confirmed,
            'level': hit.level,
            'severity': hit.severity,
            'field_only': hit.field_only,
            'rule_ids': hit.rule_ids,
            'rule_sources': hit.rule_sources,
            'evidence': [entry.to_dict() for entry in hit.evidence][:32],
            # Always present: an empty list says "nothing was matched here", which
            # is different from "this report predates原文回传".
            'matches': [dict(entry) for entry in hit.matches],
        }
        if field_name:
            item['field_name'] = str(field_name)[:128]
        if sheet_name:
            item['sheet_name'] = str(sheet_name)[:128]
        if column_index is not None:
            item['column_index'] = int(column_index)
        summary.append(item)
    return summary


def _column_categories(name: str, sample: str, *, sheet_name: str = '',
                       column_index: int | None = None
                       ) -> tuple[list[str], list[str], dict[str, int], float, list[dict]]:
    """Categories for one column, from its header name and its sampled cells.

    Returns the evidence summary as well, so the caller can report *why* a column
    was classified without ever carrying a cell value out of this function.
    ``confirmed`` is value-level evidence and drives the sensitivity; ``candidates``
    are header/context clues such as an empty template's ``phone`` column.
    """
    confirmed: list[str] = []
    candidates: list[str] = []
    counts: dict[str, int] = {}
    confidence = 0.0
    hits = engine().scan(SensitiveDetectionContext(
        text=sample or '', field_name=str(name), sheet_name=sheet_name or '',
        source_type='file'))
    for hit in hits:
        if not hit.sensitive:
            continue
        category = legacy_name(hit.entity) or hit.entity.lower()
        if not category:
            continue
        if hit.confirmed:
            if category not in confirmed:
                confirmed.append(category)
            counts[category] = counts.get(category, 0) + hit.count
            confidence = max(confidence, hit.confidence)
        elif category not in confirmed and category not in candidates:
            candidates.append(category)
    summary = _hit_summary(hits, field_name=str(name), sheet_name=sheet_name,
                           column_index=column_index)
    return confirmed, candidates, counts, round(confidence, 3), summary


def _columns_from_result(result, file_name: str) -> tuple[list[dict], list[dict], list[str]]:
    """Legacy column shape plus the engine hits behind it.

    A column's categories come from its header name and its sampled cells; the
    cells themselves never leave this function.
    """
    columns: list[dict] = []
    hits: list[dict] = []
    categories: list[str] = []
    for sheet in result.sheets:
        for column in sheet.columns:
            confirmed, candidates, counts, confidence, column_hits = _column_categories(
                column.name, column.sample_text(), sheet_name=sheet.name,
                column_index=column.index)
            hits.extend(column_hits)
            # Only value-level categories mark the *file*; header-only clues stay
            # on the column as candidates.
            for category in confirmed:
                if category not in categories:
                    categories.append(category)
            columns.append({
                'name': column.name,
                'header_name': column.name,
                'sheet_name': sheet.name,
                'column_index': column.index,
                'detected_type': (confirmed or candidates or ['text'])[0],
                'inferred_type': column.inferred_type,
                'sensitivity': _severity(confirmed) if confirmed else 'Unknown',
                'confidence': confidence,
                'categories': confirmed + [item for item in candidates if item not in confirmed],
                'confirmed_categories': confirmed,
                'candidate_categories': [item for item in candidates if item not in confirmed],
                'count': sum(counts.values()),
                'sample_size': len(column.values),
                'sample_hit_count': sum(counts.values()),
                'rule_ids': sorted({rule for hit in column_hits for rule in hit['rule_ids']}),
            })
    return columns, hits, categories


def _records_from_result(result, file_name: str) -> tuple[dict[str, int], list[str], list[dict]]:
    """Whole-file text detection: category counts, categories and evidence."""
    counts: dict[str, int] = {}
    categories: list[str] = []
    hits = engine().scan(SensitiveDetectionContext(
        text=result.text, file_name=file_name, source_type='file')) if result.text else []
    for hit in hits:
        if not hit.sensitive or not hit.count:
            continue
        category = legacy_name(hit.entity) or hit.entity.lower()
        counts[category] = counts.get(category, 0) + hit.count
        # Only value-level, sufficiently confident hits mark the whole file as
        # sensitive data; weaker shapes stay in the evidence as candidates.
        if hit.confirmed and category not in categories:
            categories.append(category)
    return counts, categories, _hit_summary(hits)


def _cache_identity(path: Path, stat, config: dict) -> tuple[str, str]:
    engine_version = str(engine().capabilities()['engine_version'])
    ruleset_version = str(config.get('ruleset_version') or 'builtin')
    return engine_version, ruleset_version


def _fingerprint_evidence(fingerprint) -> dict:
    evidence = fingerprint.as_evidence()
    # ``sha256`` stays a full-content digest for backward compatibility; a partial
    # fingerprint is reported separately and is never presented as identity.
    evidence['partial'] = not fingerprint.is_full
    return evidence


def inspect_file(path: Path, budget: ScanBudget, *, cache=None, config: dict | None = None) -> dict | None:
    """Analyse one regular file inside the shared scan budget.

    Returns ``None`` for anything that is not a regular file. Reading is bounded
    by ``budget`` for every stage - type probe, hash, sampling and parsing - so the
    per-file sample limit cannot be bypassed by a parser that reads more.
    """
    config = config or {}
    try:
        stat = path.lstat()
    except OSError:
        return None
    if not stat_module.S_ISREG(stat.st_mode):
        return None
    size = int(stat.st_size)
    suffix = path.suffix.lower()
    lower_name = path.name.lower()
    if lower_name.endswith('.sql.gz'):
        suffix = '.sql'
    if lower_name == '.env':
        suffix = '.env'

    engine_version, ruleset_version = _cache_identity(path, stat, config)
    fingerprint_digest = config_fingerprint({**config, 'engine_version': engine_version,
                                            'ruleset_version': ruleset_version})
    cache_key = key_for(str(path), stat, engine_version=engine_version,
                        ruleset_version=ruleset_version, fingerprint=fingerprint_digest)
    if cache is not None:
        cached = cache.get(cache_key)
        if cached is not None:
            cached = dict(cached)
            cached['evidence'] = {**cached.get('evidence', {}), 'cached': True}
            return cached

    record = _analyse_file(path, stat, size, suffix, budget, config)
    if record is None:
        return None
    if cache is not None and record['evidence'].get('fingerprint', {}).get('stable'):
        payload = {key: value for key, value in record.items() if key != 'evidence'}
        payload['evidence'] = {key: value for key, value in record['evidence'].items()
                               if key not in {'cached'}}
        cache.put(cache_key, path=str(path), stat=stat, engine_version=engine_version,
                  ruleset_version=ruleset_version, fingerprint=fingerprint_digest, payload=payload)
    return record


def _analyse_file(path: Path, stat, size: int, suffix: str, budget: ScanBudget, config: dict) -> dict | None:
    read_error = ''
    file_type = magic_module.detect(suffix, magic_module.probe_head(path), name=path.name)
    # The type probe itself is budget spend: it read bytes off the disk.
    budget.spend_bytes(magic_module.PROBE_BYTES if stat.st_size else 0)

    fingerprint = identify_file(path, size, max_full_hash_size=budget.max_full_hash, budget=budget)

    result = None
    try:
        result = parse_file(path, size, file_type, budget=budget)
    except BudgetExceeded:
        # The budget is exhausted: stop cleanly with what is already known.
        raise
    except OSError as exc:
        read_error = type(exc).__name__

    categories: list[str] = []
    candidate_categories: list[str] = []
    counts: dict[str, int] = {}
    columns: list[dict] = []
    hits: list[dict] = []
    coverage = 'complete'
    termination = TERMINATION_COMPLETE
    parser_name = file_type.parser
    degraded_to = ''
    parser_note = ''
    rows_read = 0
    bytes_read = fingerprint.bytes_read if not fingerprint.is_full else max(fingerprint.bytes_read, 0)
    if result is not None:
        whole_counts, whole_categories, whole_hits = _records_from_result(result, str(path.name))
        columns, column_hits, column_categories = _columns_from_result(result, str(path.name))
        hits = whole_hits + column_hits
        counts.update(whole_counts)
        for hit in column_hits:
            category = hit['category']
            counts[category] = counts.get(category, 0) + int(hit.get('count') or 0)
        for category in list(whole_categories) + list(column_categories):
            if category not in categories:
                categories.append(category)
        for hit in list(whole_hits) + list(column_hits):
            category = hit.get('category')
            if category and not hit.get('confirmed') and category not in candidate_categories:
                candidate_categories.append(category)
        coverage = result.coverage
        termination = result.termination_reason
        parser_name = result.parser
        degraded_to = result.degraded_to
        parser_note = result.note
        rows_read = result.rows_read
        bytes_read += result.bytes_read

    if suffix in DATABASE_EXTENSIONS or suffix == '.sql':
        asset_type, sensitivity = 'database', _severity(categories) if categories else 'Medium'
        categories = categories or ['database']
    elif suffix in TABLE_EXTENSIONS or file_type.kind in {magic_module.KIND_TABLE, magic_module.KIND_XLSX}:
        asset_type, sensitivity = 'table', _severity(categories)
    else:
        asset_type, sensitivity = 'file', _severity(categories)
    if not categories and candidate_categories:
        # Header/keyword clues only: review-worthy, not a discovered finding.
        sensitivity = 'Unknown'
    elif not categories and not (result and result.text):
        sensitivity = 'Low'

    if coverage != 'complete':
        budget.mark_truncated(str(path.name))
    budget.sensitive_assets += 1 if categories else 0
    budget.detections += sum(counts.values())

    return {
        'name': str(path.name)[:512],
        'asset_type': asset_type,
        'sensitivity': sensitivity,
        'path': str(path)[:1024],
        'size': size,
        'sha256': fingerprint.value if fingerprint.is_full else '',
        'modified_at': datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
        'categories': categories[:16],
        'candidate_categories': candidate_categories[:16],
        'counts': counts,
        'columns': columns[:256],
        'evidence': {
            'extension': suffix,
            'scanned_bytes': bytes_read,
            'sample_rows': SAMPLE_ROWS,
            'sampled': not fingerprint.is_full or coverage != 'complete',
            'read_error': read_error,
            'hits': hits[:256],
            'engine_version': engine().capabilities()['engine_version'],
            # Stage 3 additions: what was identified, how far the scan got, and
            # which parser produced the structure.
            'file_type': file_type.as_evidence(),
            'parser': parser_name,
            'degraded_to': degraded_to,
            'parser_note': parser_note,
            'rows_read': rows_read,
            'coverage': coverage,
            'termination_reason': termination,
            'fingerprint': _fingerprint_evidence(fingerprint),
            'inode': int(stat.st_ino),
            'device': int(stat.st_dev),
            'mtime_ns': int(stat.st_mtime_ns),
            'owner': int(stat.st_uid),
            'group': int(stat.st_gid),
            'permission': oct(stat_module.S_IMODE(stat.st_mode)),
        },
    }


def _directory_asset(path: Path, file_count: int, total_size: int, categories: list[str]) -> dict:
    """A directory node: a roll-up of the files below it, never a finding itself.

    ``categories`` is the union of the children's categories and exists only to
    label the node; ``counts`` stays empty because the directory itself holds no
    hits. ``aggregate`` says that out loud so no consumer turns the roll-up into an
    independent sensitive file.
    """
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
        'evidence': {'file_count': file_count, 'aggregate': True},
    }


def detect_local_databases(ports: dict[int, str], timeout: float = 0.4) -> list[dict]:
    """Ports that accept a TCP connection, reported as *suspected* DB services.

    A successful ``connect`` only proves something listens on that port - not
    that it speaks the engine's protocol, and certainly not that any table or
    sensitive content was found. The entry is therefore a candidate: no
    sensitive category, no severity claim, and the inference method travels in
    the evidence so a page can say "port-inferred, content not scanned".
    """
    found: list[dict] = []
    for port, engine_name in sorted(ports.items()):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=timeout):
                pass
        except OSError:
            continue
        found.append({
            'name': f'{engine_name}@127.0.0.1:{port}',
            'asset_type': 'database',
            # Nothing was read: the port is an unverified service hint, so the
            # asset must not be counted as a sensitive-data discovery.
            'sensitivity': 'Unknown',
            'path': f'127.0.0.1:{port}',
            'size': 0,
            'sha256': '',
            'modified_at': '',
            'categories': [],
            'candidate_categories': ['database', engine_name],
            'counts': {},
            'columns': [],
            'evidence': {'engine': engine_name, 'port': port, 'listening': True,
                         'discovery_method': 'port_probe',
                         'protocol_verified': False,
                         'content_scanned': False,
                         'note': '仅端口连通性推断的疑似数据库服务，未验证协议，未扫描库表内容'},
        })
    return found


def discover_data_assets(config: dict, stop_event=None, on_progress=None) -> dict:
    """Walk configured paths and return a bounded data-asset inventory.

    Every stage - type probe, hashing, sampling, parsing - spends from one
    :class:`ScanBudget`, so the report can state exactly how far the scan got.
    ``complete_scope`` is true only when the whole configured scope was covered,
    which is what the platform requires before it may mark unseen instances as
    NOT_OBSERVED.

    ``on_progress`` is called with the aggregated counters at most every
    :data:`PROGRESS_INTERVAL_SECONDS`, so a long scan can be watched without one
    HTTP request per file. Progress is best-effort: it never affects the result.
    """
    started = time.monotonic()
    paths = [Path(str(item)).expanduser() for item in (config.get('paths') or []) if str(item).strip()]
    configured = bool(paths)
    budget = ScanBudget({
        'max_files': config.get('max_files', DEFAULT_LIMITS_FALLBACK['max_files']),
        'max_depth': config.get('max_depth', DEFAULT_LIMITS_FALLBACK['max_depth']),
        'max_runtime_seconds': config.get('timeout_seconds', DEFAULT_LIMITS_FALLBACK['max_runtime_seconds']),
        'max_dirs': config.get('max_dirs', DEFAULT_LIMITS_FALLBACK['max_dirs']),
        'max_bytes_read': config.get('max_bytes_read', DEFAULT_LIMITS_FALLBACK['max_bytes_read']),
        'max_single_file_size': config.get('max_single_file_size', DEFAULT_LIMITS_FALLBACK['max_single_file_size']),
        'max_full_hash_size': config.get('max_full_hash_size', DEFAULT_LIMITS_FALLBACK['max_full_hash_size']),
        'sample_block_size': config.get('sample_block_size', DEFAULT_LIMITS_FALLBACK['sample_block_size']),
        'max_sample_rows': config.get('max_sample_rows', DEFAULT_LIMITS_FALLBACK['max_sample_rows']),
        'xlsx_max_rows': config.get('xlsx_max_rows', DEFAULT_LIMITS_FALLBACK['xlsx_max_rows']),
        'xlsx_max_entries': config.get('xlsx_max_entries', DEFAULT_LIMITS_FALLBACK['xlsx_max_entries']),
        'xlsx_max_uncompressed_bytes': config.get('xlsx_max_uncompressed_bytes',
                                                 DEFAULT_LIMITS_FALLBACK['xlsx_max_uncompressed_bytes']),
        'xlsx_max_shared_strings': config.get('xlsx_max_shared_strings',
                                              DEFAULT_LIMITS_FALLBACK['xlsx_max_shared_strings']),
        'max_cpu_seconds': config.get('max_cpu_seconds', 0),
        'max_rss_mb': config.get('max_rss_mb', 0),
    })
    budget.attach_stop_event(stop_event)
    max_depth = budget.max_depth
    include_databases = bool(config.get('include_databases', True))
    scope = scope_filter_for(config)

    cache = None
    cache_path = str(config.get('cache_path') or '').strip()
    if cache_path and config.get('cache_enabled', True):
        cache = AnalysisCache(cache_path)
        if not cache.open():
            cache = None
    scan_config = {
        'ruleset_version': str(config.get('ruleset_version') or 'builtin'),
        'max_single_file_size': budget.max_single_file,
        'max_full_hash_size': budget.max_full_hash,
        'sample_block_size': budget.block_size,
        'max_sample_rows': budget.max_rows,
        'max_depth': max_depth,
        'xlsx_max_rows': int(budget.limit('xlsx_max_rows', DEFAULT_LIMITS_FALLBACK['xlsx_max_rows'])),
    }

    assets: list[dict] = []
    scanned_paths: list[str] = []
    errors: list[str] = []
    visited: set[str] = set()
    next_progress = started

    def report_progress(*, force: bool = False) -> None:
        """Push an aggregated snapshot at a bounded rate; never raise."""
        nonlocal next_progress
        if on_progress is None:
            return
        now = time.monotonic()
        if not force and now < next_progress:
            return
        next_progress = now + max(1.0, float(PROGRESS_INTERVAL_SECONDS))
        try:
            on_progress(budget.coverage(), str(getattr(budget, 'current_path', '') or ''))
        except Exception:
            # A failed progress push must never fail the scan or hide the report.
            pass

    def walk_error(exc):
        if len(errors) < 10:
            errors.append(f'目录不可读取: {exc.filename}')

    def exhausted(exc: BudgetExceeded) -> None:
        """Record why the scan stopped; a silent break would look like success."""
        budget.stop(exc.reason, exc.detail)

    try:
        for root in paths:
            try:
                budget.check()
            except BudgetExceeded:
                break
            try:
                mode = root.lstat().st_mode
                if stat_module.S_ISLNK(mode):
                    errors.append(f'不采集符号链接目录: {root}')
                    continue
                if not stat_module.S_ISDIR(mode):
                    errors.append(f'指定路径不是目录: {root}')
                    continue
            except FileNotFoundError:
                errors.append(f'目录不存在: {root}')
                continue
            except PermissionError:
                errors.append(f'无权限访问目录: {root}')
                continue
            except OSError as exc:
                errors.append(f'目录访问失败（{type(exc).__name__}）: {root}')
                continue
            root = root.absolute()
            if scope.excludes_path(str(root)):
                scope.note_directory()
                continue
            scanned_paths.append(str(root))
            for current, subdirs, files in _walk(root, max_depth, walk_error):
                try:
                    budget.note_directory()
                    budget.check()
                except BudgetExceeded as exc:
                    exhausted(exc)
                    break
                kept: list[str] = []
                for item in sorted(subdirs):
                    if item in SKIP_DIRECTORIES or item.startswith('.docker'):
                        continue
                    if scope.excludes_directory(item, os.path.join(str(current), item)):
                        scope.note_directory()
                        continue
                    kept.append(item)
                subdirs[:] = kept
                total_size = 0
                counted = 0
                directory_categories: set[str] = set()
                for name in sorted(files):
                    path = Path(current) / name
                    key = str(path)
                    if key in visited or path.is_symlink():
                        budget.note_skip()
                        continue
                    visited.add(key)
                    # Configured exclusions and the type allow-list are scope, not
                    # budget: they are reported separately so a filtered scan is not
                    # mistaken for a truncated one (which is what Partial means).
                    if scope.excludes_path(key):
                        scope.note_excluded_file()
                        continue
                    if not scope.allows_file(name):
                        scope.note_filtered_file()
                        continue
                    try:
                        budget.check()
                        budget.note_file()
                        record = inspect_file(path, budget, cache=cache, config=scan_config)
                    except BudgetExceeded as exc:
                        exhausted(exc)
                        break
                    if not record:
                        budget.note_skip()
                        continue
                    if record['evidence'].get('read_error'):
                        errors.append(f'文件不可读取: {path}')
                    # The walker owns the rate limit, so a large tree produces one
                    # aggregated progress push every few seconds and never one per file.
                    budget.current_path = str(path)[:1024]
                    report_progress()
                    total_size += record['size']
                    counted += 1
                    directory_categories.update(record['categories'])
                    assets.append(record)
                if counted:
                    assets.append(_directory_asset(Path(current), counted, total_size,
                                                   sorted(directory_categories)))
                if not budget.enumeration_complete:
                    break
            if not budget.enumeration_complete:
                break
        databases = []
        if include_databases:
            for port, engine_name in LOCAL_DATABASE_SERVICES.items():
                try:
                    budget.check()
                except BudgetExceeded as exc:
                    exhausted(exc)
                    break
                databases.extend(detect_local_databases({port: engine_name},
                                                        timeout=min(.4, max(.01, budget.remaining_seconds()))))
    except BudgetExceeded as exc:
        exhausted(exc)
    finally:
        if cache is not None:
            cache.close()

    if not configured:
        budget.stop(TERMINATION_UNCONFIGURED, '未配置采集目录')
    elif errors:
        # A path the walk could not read leaves a hole in the report. Recording it
        # as the termination reason keeps ``complete_scope`` false, so a scan with
        # holes can never be presented as a finished one.
        budget.stop(TERMINATION_UNREADABLE, '; '.join(errors)[:255])
    report_progress(force=True)
    coverage = budget.coverage()
    if scope.active:
        coverage['scope_filter'] = scope.evidence(config.get('exclude_paths'), config.get('file_types'))
    if cache is not None:
        coverage['cache'] = cache.stats.as_evidence()
    counts: dict[str, int] = {}
    for item in assets:
        for category in item.get('categories', []):
            counts[category] = counts.get(category, 0) + 1
    error = '; '.join(errors)[:500] if configured else '未配置数据资产采集目录（agent.paths / data.paths）'
    return {
        'assets': assets,
        'databases': databases,
        'scanned_paths': scanned_paths,
        'counts': counts,
        'max_depth': max_depth,
        # ``complete`` keeps its original meaning for the platform's compatibility
        # branch; ``coverage.complete_scope`` is the precise statement.
        'complete': bool(scanned_paths) and budget.complete and not errors,
        'error': error,
        'observed_at': datetime.now(UTC).isoformat(),
        'scanner': 'probe-file-inventory',
        'location': 'probe',
        'engine_version': engine().capabilities()['engine_version'],
        'ruleset_version': str(config.get('ruleset_version') or ''),
        'duration_ms': int((time.monotonic() - started) * 1000),
        'coverage': coverage,
        # Stage 4: the platform needs an unambiguous statement of scope coverage
        # before it may mark unseen instances as NOT_OBSERVED, plus the schema and
        # version fields that make a report reproducible after the fact.
        'schema_version': REPORT_SCHEMA_VERSION,
        'scan_id': str(config.get('scan_id') or ''),
        'profile_version': str(config.get('profile_version') or ''),
        'completed_scope': bool(scanned_paths) and budget.complete and not errors,
        'termination_reason': coverage['termination_reason'],
        'budget': dict(coverage),
        'totals': {
            'assets': len(assets),
            'databases': len(databases),
            'sensitive_assets': coverage['sensitive_assets'],
            'detections': coverage['detections'],
        },
        # Named, not implied: a server that sees a capability here knows the probe
        # did less than a fully capable one would have.
        'degraded_capabilities': [] if budget.limit('large_file_sampling', True) else
        ['large_file_sampler'],
    }


def guard_report(report: dict) -> dict:
    """Final safety net before a report leaves the host.

    Runs once for every data-asset report, after the report id and task id are
    attached: forbidden payload keys are dropped and any string that still looks
    like a raw value is redacted. The audit counts travel with the report so a
    real redaction is visible in the platform instead of silently swallowed, and
    the platform rejects a payload that contradicts this guard.
    """
    clean, audit = sanitize_report(report)
    clean['report_guard'] = audit.to_dict()
    return clean


def _walk(root: Path, max_depth: int, onerror=None):
    """os.walk wrapper honouring the depth limit without loading the whole tree."""
    import os

    base_depth = len(root.parts)
    for current, subdirs, files in os.walk(root, followlinks=False, onerror=onerror):
        depth = len(Path(current).parts) - base_depth
        if depth >= max_depth:
            subdirs[:] = []
        yield current, subdirs, files
