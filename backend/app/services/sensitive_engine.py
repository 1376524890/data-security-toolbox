"""Adapter between the shared detection engine and the platform.

The platform and the probe must never drift, so this module is a thin binding:
it locates the ``shared`` package, exposes one cached engine, and converts shared
results into the legacy dictionaries the existing engines and pages still read.

No detection logic lives here.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Iterable

SHARED_PACKAGE = "shared"


def _bootstrap_shared_path() -> Path | None:
    """Make ``shared`` importable in dev, in Docker and in the test harness."""
    candidates: list[Path] = []
    override = os.environ.get("SHARED_LIBRARY_DIR")
    if override:
        candidates.append(Path(override))
    # backend/app/services/sensitive_engine.py -> <repo>/
    candidates.append(Path(__file__).resolve().parents[3])
    candidates.append(Path(__file__).resolve().parents[2])
    candidates.append(Path("/app"))
    candidates.append(Path.cwd())
    for candidate in candidates:
        if (candidate / SHARED_PACKAGE / "sensitive_detection" / "engine.py").is_file():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            return candidate
    return None


SHARED_ROOT = _bootstrap_shared_path()

from shared.sensitive_detection import (  # noqa: E402
    ENGINE_VERSION,
    SensitiveDetectionContext,
    SensitiveDetectionEngine,
    build_engine,
    text_matches,
)
from shared.sensitive_detection import entities as shared_entities  # noqa: E402
from shared.sensitive_detection.matching import REGEX_BACKEND, SUPPORTS_TIMEOUT  # noqa: E402

_ENGINE: SensitiveDetectionEngine | None = None

# The console's own rules (the "手动添加规则" / Presidio ones) live in the rule
# store as plain JSON, not in the shared builtin pack. They are scanned by the
# same engine with the same bounds, so one rule means one thing everywhere: a
# keyword added for the network DLP stage is also found in a file, a database
# column and a probe report.
_ANALYST_VALIDATORS = {"EMAIL": "email_shape", "EMAIL_ADDRESS": "email_shape"}
_SCAN_ENGINE: tuple[tuple, SensitiveDetectionEngine] | None = None


def get_engine() -> SensitiveDetectionEngine:
    """One process-wide engine built from the built-in rule pack."""
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = build_engine()
    return _ENGINE


def engine_metadata() -> dict[str, Any]:
    return {
        "engine_version": ENGINE_VERSION,
        "regex_backend": REGEX_BACKEND,
        "regex_timeout": SUPPORTS_TIMEOUT,
        "shared_root": str(SHARED_ROOT or ""),
        "rule_count": len(get_engine().rules),
    }


def scan_text(text: str, **context: Any) -> list[Any]:
    return get_engine().scan_text(text, **context)


def analyst_rules() -> list[dict[str, Any]]:
    """The rule store's manual / imported rules in shared rule format.

    The field mapping itself belongs to the store (``rule_library.stored_rule``)
    so the rule-set working copy a probe downloads is built from the same
    fields, not from a second reading of the same JSON.
    """
    from app.services.rule_library import managed_rules, stored_rule

    rules: list[dict[str, Any]] = []
    for raw in managed_rules():
        rule = stored_rule(raw)
        if not rule["rule_id"] or not rule["pattern"]:
            # A rule without an id cannot be traced back to its author; a rule
            # without a pattern is the engine's built-in set's business.
            continue
        entity = canonical_entity(rule["entity"])
        # Upstream packs match the host part of connection strings as an
        # "email"; the same shape check the builtin email rule uses applies.
        rules.append({**rule, "entity": entity, "level": level_of(entity),
                      "validator": _ANALYST_VALIDATORS.get(entity, "")})
    return rules


def analyst_signature() -> tuple:
    """Cheap identity of the rule store, so a rule edit is picked up at once."""
    from app.services.rule_library import rule_store_files

    signature: list[tuple[str, int, int]] = []
    try:
        paths = rule_store_files()
    except OSError:
        return ()
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            continue
        signature.append((str(path), stat.st_mtime_ns, stat.st_size))
    return tuple(signature)


def scan_engine() -> SensitiveDetectionEngine:
    """Builtin pack plus the rule store: what every platform scan runs."""
    global _SCAN_ENGINE
    signature = analyst_signature()
    if _SCAN_ENGINE is not None and _SCAN_ENGINE[0] == signature:
        return _SCAN_ENGINE[1]
    engine = SensitiveDetectionEngine(get_engine().rules)
    for rule in analyst_rules():
        engine.add_rule(rule)
    _SCAN_ENGINE = (signature, engine)
    return engine


def scan_all(text: str, **context: Any) -> list[Any]:
    """Scan with the builtin pack and the analyst rules together."""
    return scan_engine().scan_text(text, **context)


def has_analyst_rule(hit: Any) -> bool:
    """Whether any evidence behind a hit came from a console-authored rule."""
    return any(str(source) != "builtin" for source in hit.rule_sources)


def legacy_name(entity: object) -> str:
    return shared_entities.legacy_name(entity)


def level_of(entity: object) -> str:
    return shared_entities.level_of(entity)


def severity_of(entity: object) -> str:
    return shared_entities.severity_of(entity)


def severity_of_level(level: object) -> str:
    return shared_entities.severity_of_level(level)


def known_entities() -> tuple[str, ...]:
    return shared_entities.known_entities()


def canonical_entity(entity: object) -> str:
    return shared_entities.canonical_entity(entity)


def is_structural(entity: object) -> bool:
    """True for infrastructure metadata (IPs, dates): evidence, never data."""
    return shared_entities.is_structural(entity)


def is_field_only(entity: object) -> bool:
    """True when P0 only has field/context evidence for this type (no NER)."""
    return shared_entities.is_field_only(entity)


def compiled_pattern(rule: dict[str, Any]) -> Any:
    """Compile a registered rule's pattern with the engine's bounds."""
    return get_engine().rule_pattern(rule)


def to_legacy_hits(hits: Iterable[Any], categories: Iterable[str] | None = None,
                   *, include_matches: bool = False) -> list[dict[str, Any]]:
    """Shared hits -> the legacy ``{'kind', 'count', 'confidence', ...}`` shape.

    ``categories`` filters by legacy lowercase category, matching how the stored
    DLP policy lists the types it cares about.

    ``include_matches`` adds the bounded matched原文 (value plus its line). It is
    opt-in because most callers only need the count; the network DLP stage asks
    for it so an operator can read what was actually transmitted.

    A hit keeps the entity an analyst wrote (``COMPANY``, ``测试``) rather than a
    lower-cased form: a rule the console shows must be recognisable in the
    result, and only the builtin pack has a legacy lower-case name to fall back
    on.
    """
    wanted = {str(item).lower() for item in categories} if categories is not None else None
    converted: list[dict[str, Any]] = []
    for hit in hits:
        name = legacy_name(hit.entity) or str(hit.entity)
        if wanted is not None and name.lower() not in wanted:
            continue
        entry = {
            "kind": name,
            "entity": hit.entity,
            "count": hit.count,
            "confidence": hit.confidence,
            "sensitive": hit.sensitive,
            "field_only": hit.field_only,
            "level": hit.level,
            "severity": hit.severity,
            "rule_ids": hit.rule_ids,
            "rule_sources": hit.rule_sources,
            "evidence": [item.to_dict() for item in hit.evidence],
        }
        if include_matches:
            entry["matches"] = [dict(item) for item in hit.matches]
        converted.append(entry)
    return converted


def count_by_legacy_name(hits: Iterable[Any]) -> dict[str, int]:
    """Legacy ``{category: count}`` map, adding nothing for absent types."""
    counts: dict[str, int] = {}
    for hit in hits:
        name = legacy_name(hit.entity)
        if name:
            counts[name] = counts.get(name, 0) + hit.count
    return counts


def pii_count(hits: Iterable[Any]) -> int:
    families = {"PHONE", "ID_CARD", "BANK_CARD", "EMAIL", "NAME", "ADDRESS", "MEDICAL_RECORD"}
    return sum(hit.count for hit in hits if hit.entity in families)


def secret_count(hits: Iterable[Any]) -> int:
    families = {"API_KEY", "TOKEN", "CREDENTIAL"}
    return sum(hit.count for hit in hits if hit.entity in families)


def confirmed_hits(hits: Iterable[Any]) -> list[Any]:
    """Hits with value-level evidence: what an alert or a risk label may use."""
    return [hit for hit in hits if hit.sensitive and hit.confirmed]


def candidate_hits(hits: Iterable[Any]) -> list[Any]:
    """Field/keyword/context-only clues. Visible as evidence, never an alert."""
    return [hit for hit in hits if hit.sensitive and not hit.confirmed]


def max_confidence(hits: Iterable[Any]) -> float:
    return round(max((float(hit.confidence) for hit in hits), default=0.0), 4)


def text_truncated() -> bool:
    """Whether the last scan had to cut the text before the end."""
    return bool(scan_engine().last_report.text_truncated)


def scan_timeouts() -> list[str]:
    """Rule ids whose pattern hit the per-rule time bound during the last scan."""
    return sorted(set(scan_engine().last_report.timeouts))


__all__ = [
    "SensitiveDetectionContext",
    "SensitiveDetectionEngine",
    "engine_metadata",
    "get_engine",
    "scan_text",
    "scan_all",
    "scan_engine",
    "analyst_rules",
    "analyst_signature",
    "has_analyst_rule",
    "to_legacy_hits",
    "count_by_legacy_name",
    "pii_count",
    "secret_count",
    "confirmed_hits",
    "candidate_hits",
    "max_confidence",
    "text_truncated",
    "scan_timeouts",
    "legacy_name",
    "text_matches",
    "level_of",
    "severity_of",
    "severity_of_level",
    "known_entities",
    "canonical_entity",
    "is_structural",
    "is_field_only",
    "ENGINE_VERSION",
]
