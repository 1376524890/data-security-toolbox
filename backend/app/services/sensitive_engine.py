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
)
from shared.sensitive_detection import entities as shared_entities  # noqa: E402
from shared.sensitive_detection.matching import REGEX_BACKEND, SUPPORTS_TIMEOUT  # noqa: E402

_ENGINE: SensitiveDetectionEngine | None = None


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


def to_legacy_hits(hits: Iterable[Any], categories: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Shared hits -> the legacy ``{'kind', 'count', 'confidence', ...}`` shape.

    ``categories`` filters by legacy lowercase category, matching how the stored
    DLP policy lists the types it cares about.
    """
    wanted = {str(item).lower() for item in categories} if categories is not None else None
    converted: list[dict[str, Any]] = []
    for hit in hits:
        name = legacy_name(hit.entity) or str(hit.entity).lower()
        if wanted is not None and name not in wanted:
            continue
        converted.append({
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
        })
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
    return bool(get_engine().last_report.text_truncated)


__all__ = [
    "SensitiveDetectionContext",
    "SensitiveDetectionEngine",
    "engine_metadata",
    "get_engine",
    "scan_text",
    "to_legacy_hits",
    "count_by_legacy_name",
    "pii_count",
    "secret_count",
    "confirmed_hits",
    "candidate_hits",
    "max_confidence",
    "text_truncated",
    "legacy_name",
    "level_of",
    "severity_of",
    "severity_of_level",
    "known_entities",
    "canonical_entity",
    "is_structural",
    "is_field_only",
    "ENGINE_VERSION",
]
