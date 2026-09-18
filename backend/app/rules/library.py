"""Read the platform rule library: which files exist and what they configure.

Engines used to carry their thresholds as literals in Python, so the console had
no rules to show for them and an operator could not change a threshold without a
rebuild. Every engine now reads its parameters from the rule files listed in
``catalog.CATALOG``; the code keeps its original values as the fallback used when
a file is absent, disabled or malformed, so a bad edit can never stop detection.

Files are read through a small mtime cache: rule evaluation happens per analysis
job, and the library rarely changes.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.config import settings
from app.rules.catalog import RuleSource, for_engine

logger = logging.getLogger(__name__)

_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def _load_document(path: Path) -> list[dict[str, Any]]:
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        return []
    cached = _CACHE.get(str(path))
    if cached and cached[0] == stamp:
        return cached[1]
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        # A malformed rule file must not take the engine down, but it must be
        # visible: silently keeping the built-in values hides operator mistakes.
        logger.warning("rule file %s is not valid YAML; falling back to built-in values", path)
        entries: list[dict[str, Any]] = []
    else:
        if isinstance(document, dict):
            entries = [document]
        elif isinstance(document, list):
            entries = [item for item in document if isinstance(item, dict)]
        else:
            entries = []
    _CACHE[str(path)] = (stamp, entries)
    return entries


def runtime_directory(source: RuleSource) -> Path | None:
    """Where an online refresh stores this engine's downloaded rules."""
    return settings.integration_dir / source.runtime_dir if source.runtime_dir else None


def rule_files(engine: str) -> list[Path]:
    """Every rule file the library holds for one engine, in a stable order."""
    source: RuleSource | None = for_engine(engine)
    if source is None:
        return []
    found: list[Path] = []
    for directory in source.directories:
        if not directory.is_dir():
            continue
        for pattern in source.patterns:
            iterator = directory.rglob(pattern) if source.recursive else directory.glob(pattern)
            found.extend(path for path in iterator if path.is_file())
    runtime = runtime_directory(source)
    if runtime and runtime.is_dir():
        manifest = runtime / "active.json"
        if manifest.is_file():
            try:
                generation = json.loads(manifest.read_text(encoding="utf-8"))["generation"]
                candidate = (runtime / generation).resolve()
                candidate.relative_to(runtime.resolve())
                runtime = candidate
            except (ValueError, KeyError, OSError):
                logger.warning("Invalid rule generation manifest: %s", manifest)
                return sorted({path.resolve() for path in found})
        for pattern in source.patterns:
            found.extend(sorted(path for path in runtime.glob(pattern) if path.is_file()))
        # Downloaded repos keep their own layout (rules/et_open/...).
        for pattern in source.patterns:
            found.extend(sorted(path for path in runtime.rglob(pattern) if path.is_file()))
    # A file may match several patterns (``*.yaml`` and ``*.yml``); keep one copy.
    return sorted({path.resolve() for path in found})


def rule_entries(engine: str) -> list[dict[str, Any]]:
    """Flattened rule entries for one engine, each carrying its source file."""
    entries: list[dict[str, Any]] = []
    for path in rule_files(engine):
        if path.suffix not in {".yaml", ".yml"}:
            continue
        for item in _load_document(path):
            entries.append({**item, "_file": path.name, "_path": str(path)})
    return entries


def rule_entry(engine: str, rule_id: str) -> dict[str, Any] | None:
    for item in rule_entries(engine):
        if str(item.get("rule_id") or item.get("id") or "") == rule_id:
            return item
    return None


def rule_policy(engine: str, rule_id: str, default: dict[str, Any] | None = None) -> dict[str, Any]:
    """The ``params`` mapping of one enabled rule, without rule metadata merged in.

    Data-driven rules (the DLP policy) configure a whole subsystem, so the
    caller needs the parameters alone -- rule_id/severity/title must not leak
    into a policy object that other code iterates over.
    """
    fallback = dict(default or {})
    entry = rule_entry(engine, rule_id)
    if not entry or entry.get("enabled") is False:
        return fallback
    params = entry.get("params")
    return {**fallback, **params} if isinstance(params, dict) else fallback


def rule_enabled(engine: str, rule_id: str) -> bool:
    """Whether a rule should run at all.

    A rule the library does not carry keeps the behaviour the engine was built
    with; only an explicit ``enabled: false`` in a rule file turns it off.
    """
    entry = rule_entry(engine, rule_id)
    if entry is None:
        return True
    return entry.get("enabled") is not False


def rule_params(engine: str, rule_id: str, default: dict[str, Any] | None = None) -> dict[str, Any]:
    """Parameters of one enabled rule, or ``default`` when the rule is absent.

    Parameters live under ``params``; the rule's own scalar fields are merged
    underneath so a rule file may set either ``params.threshold`` or a top-level
    ``threshold``.
    """
    fallback = dict(default or {})
    entry = rule_entry(engine, rule_id)
    if not entry or entry.get("enabled") is False:
        return fallback
    values = {key: value for key, value in entry.items()
              if key not in {"params", "recommendation", "condition", "title"}}
    params = entry.get("params")
    if isinstance(params, dict):
        values.update(params)
    fallback.update(values)
    # Invalid threshold types must not abort an entire capture analysis.
    for key, original in (default or {}).items():
        value = fallback.get(key)
        if isinstance(original, (int, float)) and not isinstance(original, bool):
            try:
                number = type(original)(value)
                if number < 0 or number != number or number == float("inf"):
                    raise ValueError("invalid threshold")
                fallback[key] = number
            except (TypeError, ValueError, OverflowError):
                fallback[key] = original
        elif isinstance(original, list) and not isinstance(value, list):
            fallback[key] = original
    return fallback


def rule_snapshot(engine: str, rule_id: str) -> dict | None:
    if engine == 'suricata' and rule_id.removeprefix('SURICATA_').isdigit():
        sid = rule_id.removeprefix('SURICATA_')
        for path in rule_files(engine):
            line = _suricata_lines(str(path), path.stat().st_mtime_ns).get(sid)
            if line:
                title = re.search(r'msg\s*:\s*"([^"\n]+)"', line)
                return {
                    'rule_id': rule_id, 'engine': engine, 'type': 'suricata',
                    'title': title.group(1) if title else rule_id, 'condition': line,
                    'path': str(path), 'file': path.name, 'content': line,
                    'sha256': hashlib.sha256(line.encode()).hexdigest(),
                    'recommendation': '根据签名与原始流量核实并处置。',
                }
    if engine == 'zeek' and rule_id.startswith('ZEEK_DST_'):
        source = for_engine('zeek').directories[0] / 'site_security.zeek'
        content = source.read_text(encoding='utf-8')
        return {'rule_id': rule_id, 'engine': engine, 'type': 'zeek',
                'title': rule_id, 'condition': 'Zeek 站点策略产生对应 Notice',
                'content': content, 'path': str(source), 'file': source.name,
                'sha256': hashlib.sha256(content.encode()).hexdigest()}
    entry = rule_entry(engine, rule_id)
    if entry:
        path = Path(entry["_path"])
        content = path.read_text(encoding="utf-8")
        result = {
            "rule_id": rule_id, "engine": engine, "type": "configured",
            "title": entry.get("title", rule_id), "severity": entry.get("severity", ""),
            "condition": entry.get("condition", ""),
            "recommendation": entry.get("recommendation", ""),
            "path": str(path), "file": path.name, "content": content,
            "detection": entry.get("params") or entry.get("detection"),
        }
    else:
        from app.rules.code_catalog import definition

        result = definition(engine, rule_id)
    if result:
        result["sha256"] = hashlib.sha256(result["content"].encode()).hexdigest()
    return result


@lru_cache(maxsize=256)
def _suricata_lines(filename: str, stamp: int) -> dict[str, str]:
    result = {}
    for line in Path(filename).read_text(encoding='utf-8', errors='replace').splitlines():
        if line.lstrip().startswith('#'):
            continue
        match = re.search(r'\bsid\s*:\s*(\d+)\s*;', line)
        if match:
            result[match.group(1)] = line
    return result




def clear_cache() -> None:
    _CACHE.clear()
