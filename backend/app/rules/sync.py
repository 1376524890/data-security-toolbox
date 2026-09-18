"""Refresh engine rule sets from the publishers that maintain them.

The platform authors the rules its own engines run; the third-party engines
publish theirs. This module pulls those published rule sets into the runtime
library directory so coverage does not freeze at whatever version shipped in the
image.

Nothing here invents a rule. A download is validated in the engine's own format
before it is stored, the number of files and bytes is capped, and a source that
is unreachable (an offline deployment, a blocked egress) leaves the existing rule
set untouched and reports the failure instead of silently keeping stale rules.
"""
from __future__ import annotations

import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests
import yaml

from app.rules import library
from app.rules.catalog import RuleSource, for_engine

# A rule set is data, not a payload: refuse anything that would fill the volume.
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_STORED_FILES = 15000
MAX_STORED_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024

SIGMA_URL = "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master"
ZEEK_URL = "https://codeload.github.com/zeek/zeek/zip/refs/heads/master"
OSQUERY_URL = "https://codeload.github.com/osquery/osquery/zip/refs/heads/master"
SURICATA_URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"


@dataclass
class SyncResult:
    engine: str
    status: str
    source: str = ""
    files: int = 0
    bytes: int = 0
    stored: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine, "status": self.status, "source": self.source,
            "files": self.files, "bytes": self.bytes, "stored": self.stored[:20],
            "detail": self.detail,
        }


def _download(url: str, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """Stream a download and stop before an oversized body reaches memory."""
    with requests.get(url, timeout=(10, 180), stream=True, allow_redirects=True) as response:
        response.raise_for_status()
        declared = int(response.headers.get("content-length") or 0)
        if declared > max_bytes:
            raise ValueError(f"上游体积 {declared} 字节超过上限 {max_bytes}")
        buffer = io.BytesIO()
        for chunk in response.iter_content(64 * 1024):
            buffer.write(chunk)
            if buffer.tell() > max_bytes:
                raise ValueError(f"上游体积超过上限 {max_bytes} 字节")
        return buffer.getvalue()


def _valid_sigma(text: str) -> bool:
    try:
        document = yaml.safe_load(text)
    except Exception:
        return False
    from app.rules.sigma import supported_document

    return supported_document(document)


def _valid_yaml(text: str) -> bool:
    try:
        return isinstance(yaml.safe_load(text), (dict, list))
    except Exception:
        return False


def _valid_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except Exception:
        return False


def _valid_xml(text: str) -> bool:
    import xml.etree.ElementTree as element_tree
    try:
        element_tree.fromstring('<rules>' + text + '</rules>')
        return True
    except Exception:
        return False


def _valid_suricata(text: str) -> bool:
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return "sid:" in body


def _valid_sql(text: str) -> bool:
    return "select" in text.lower()


def _valid_zeek(text: str) -> bool:
    return "event " in text or "@load" in text or "redef " in text


# One validator per file type, keyed by suffix: an upstream file that does not
# parse in its own format is dropped instead of being served to an engine.
VALIDATORS: dict[str, Callable[[str], bool]] = {
    ".yml": _valid_sigma,
    ".yaml": _valid_sigma,
    ".xml": _valid_xml,
    ".conf": _valid_json,
    ".rules": _valid_suricata,
    ".sql": _valid_sql,
    ".zeek": _valid_zeek,
}


def _runtime_dir(engine: str) -> Path:
    source = for_engine(engine)
    if source is None or not source.runtime_dir:
        raise ValueError(f"{engine} 没有在线规则目录")
    directory = library.runtime_directory(source)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _open_archive(payload: bytes, url: str) -> tuple[Any, bool]:
    stream = io.BytesIO(payload)
    if url.endswith((".tar.gz", ".tgz")):
        return tarfile.open(fileobj=stream, mode="r:gz"), True
    return zipfile.ZipFile(stream), False


def _member_name(member: Any, is_tar: bool) -> str:
    """Archive entry name: tarfile exposes ``name``, zipfile ``filename``."""
    return member.name if is_tar else getattr(member, "filename", "")


def _member_is_directory(member: Any, name: str, is_tar: bool) -> bool:
    return member.isdir() if is_tar else name.endswith("/")


def _store_archive(engine: str, url: str, include: Callable[[str], bool],
                   allowed: tuple[str, ...], result: SyncResult) -> None:
    """Publish a complete validated generation; readers keep the old one on failure."""
    directory = _runtime_dir(engine)
    archive, is_tar = _open_archive(_download(url), url)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=directory))
    skipped = 0
    try:
        with archive:
            for member in archive.getmembers() if is_tar else archive.infolist():
                name = _member_name(member, is_tar)
                if _member_is_directory(member, name, is_tar) or not include(name):
                    continue
                if not any(name.lower().endswith(suffix) for suffix in allowed):
                    continue
                if is_tar and not member.isfile():
                    continue
                size = member.size if is_tar else member.file_size
                if size > MAX_MEMBER_BYTES or result.bytes + size > MAX_STORED_BYTES:
                    raise ValueError("规则包解压大小超过上限，保留旧版本")
                if result.files >= MAX_STORED_FILES:
                    raise ValueError("规则包文件数超过上限，保留旧版本")
                # Never extract archive paths or links directly.
                parts = name.replace('\\', '/').split('/')
                if any(part in {'..', ''} for part in parts) or ':' in name:
                    raise ValueError("规则包包含非法路径")
                stream = archive.extractfile(member) if is_tar else archive.open(member)
                with stream:
                    raw = stream.read(MAX_MEMBER_BYTES + 1)
                if len(raw) > MAX_MEMBER_BYTES:
                    raise ValueError("规则文件过大")
                content = raw.decode("utf-8")
                validator = VALIDATORS.get(Path(name).suffix.lower())
                if engine == 'openscap':
                    import xml.etree.ElementTree as ET
                    validator = lambda value: ET.fromstring(value).tag.endswith('data-stream-collection')
                if validator is None or not validator(content):
                    skipped += 1
                    continue
                target = staging.joinpath(*parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                result.files += 1
                result.bytes += len(raw)
                result.stored.append('/'.join(parts))
        if not result.files:
            raise ValueError("未找到兼容规则，保留旧版本")
        if engine == 'suricata':
            binary = shutil.which('suricata')
            if not binary:
                raise ValueError("缺少 Suricata，无法校验规则，保留旧版本")
            merged = staging / 'validation.rules'
            paths = sorted(staging.rglob('*.rules'))
            merged.write_text('\n'.join(p.read_text(encoding='utf-8') for p in paths), encoding='utf-8')
            check = subprocess.run([binary, '-T', '-S', str(merged), '-l', str(staging)],
                                   capture_output=True, text=True, timeout=180)
            merged.unlink()
            if check.returncode:
                raise ValueError('Suricata 规则校验失败: ' + (check.stderr + check.stdout)[-1500:])
        generation = 'generation-' + uuid.uuid4().hex
        staging.rename(directory / generation)
        from app.services.rule_library import atomic_json

        atomic_json(directory / 'active.json', {'generation': generation, 'source': url})
        library.clear_cache()
        mode = '已激活' if engine in {'sigma_log_engine', 'suricata'} else '已下载，外部组件规则待部署'
        result.detail = f'{mode} {result.files} 个文件；跳过不兼容文件 {skipped} 个'
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def _refresh_sigma(engine: str, result: SyncResult) -> None:
    _store_archive(
        engine, SIGMA_URL,
        include=lambda name: "/rules/" in name and "/deprecated/" not in name and "/unsupported/" not in name,
        allowed=(".yml", ".yaml"), result=result,
    )


def _refresh_zeek(engine: str, result: SyncResult) -> None:
    _store_archive(
        engine, ZEEK_URL,
        include=lambda name: "/scripts/" in name and "/policy/" in name,
        allowed=(".zeek",), result=result,
    )


def _refresh_osquery(engine: str, result: SyncResult) -> None:
    _store_archive(
        engine, OSQUERY_URL,
        include=lambda name: "/packs/" in name,
        allowed=(".conf",), result=result,
    )


def _refresh_wazuh(engine: str, result: SyncResult) -> None:
    release = json.loads(_download('https://api.github.com/repos/wazuh/wazuh/releases/latest',
                                   2 * 1024 * 1024))
    version = release['tag_name']
    if not version.replace('.', '').replace('-', '').isalnum():
        raise ValueError('无效上游版本')
    _store_archive(
        engine, f'https://codeload.github.com/wazuh/wazuh/zip/refs/tags/{version}',
        include=lambda name: "/ruleset/rules/" in name,
        allowed=(".xml",), result=result,
    )


def _refresh_suricata(engine: str, result: SyncResult) -> None:
    _store_archive(
        engine, SURICATA_URL,
        include=lambda name: name.endswith(".rules"),
        allowed=(".rules",), result=result,
    )


def _refresh_presidio(engine: str, result: SyncResult) -> None:
    """Presidio publishes its recognizers inside the analyzer wheel."""
    from app.services import rule_library

    outcome = rule_library.update_presidio()
    result.files = int(outcome.get("imported") or 0)
    result.bytes = 0
    result.stored = ["presidio.json（DLP 规则库）"]
    result.detail = (f"已导入识别器 {result.files} 条，跳过 {outcome.get('skipped', 0)} 条，"
                     f"版本 {outcome.get('version', '')}")


def _refresh_openscap(engine: str, result: SyncResult) -> None:
    release = json.loads(_download(
        'https://api.github.com/repos/ComplianceAsCode/content/releases/latest', 2 * 1024 * 1024
    ))
    asset = next(item for item in release['assets']
                 if item['name'].startswith('scap-security-guide-') and item['name'].endswith('.zip'))
    platforms = {'ssg-debian12-ds.xml', 'ssg-debian13-ds.xml',
                 'ssg-ubuntu2204-ds.xml', 'ssg-ubuntu2404-ds.xml'}
    _store_archive(engine, asset['browser_download_url'],
                   include=lambda name: Path(name).name in platforms,
                   allowed=('.xml',), result=result)


REFRESHERS: dict[str, Callable[[str, SyncResult], None]] = {
    "sigma": _refresh_sigma,
    "zeek": _refresh_zeek,
    "osquery": _refresh_osquery,
    "wazuh": _refresh_wazuh,
    "suricata": _refresh_suricata,
    "presidio": _refresh_presidio,
    "openscap": _refresh_openscap,
}


def refresh(engine: str) -> SyncResult:
    """Fetch one engine's upstream rule set into the runtime library."""
    source: RuleSource | None = for_engine(engine)
    if source is None:
        return SyncResult(engine=engine, status="failed", detail="未知引擎")
    if not source.refreshable:
        return SyncResult(engine=engine, status="skipped", detail="该引擎的规则由平台维护，无上游可拉取")
    refresher = REFRESHERS.get(source.fetch)
    if refresher is None:
        return SyncResult(engine=engine, status="failed", detail=f"未实现的拉取方式 {source.fetch}")
    result = SyncResult(engine=engine, status="updated", source=source.source_url)
    try:
        refresher(engine, result)
    except Exception as exc:
        return SyncResult(engine=engine, status="failed", source=source.source_url,
                          files=result.files, detail=f"{type(exc).__name__}: {exc}")
    if result.files == 0:
        result.status = "empty"
        result.detail = result.detail or "上游未提供可用的规则文件"
    else:
        result.detail = result.detail or f"已更新 {result.files} 个规则文件"
    return result


def sources() -> list[dict[str, Any]]:
    """Every refreshable engine with the publisher its rules come from."""
    from app.rules.catalog import CATALOG

    return [
        {"engine": item.engine, "label": item.label, "source_name": item.source_name,
         "source_url": item.source_url, "fetch": item.fetch, "scope": item.scope,
         "runtime_dir": item.runtime_dir}
        for item in CATALOG if item.refreshable
    ]
