"""Unified sensitive-data detection shared by the probe and the platform.

One rule set, one alias table, one validator set and one confidence model for
every caller: probe-side file discovery, platform-side file analysis and the
network DLP text stage. Import :func:`build_engine` for the built-in rule set or
construct :class:`~.engine.SensitiveDetectionEngine` from a published rule pack.
"""
from .context import SensitiveDetectionContext
from .entities import canonical_entity, legacy_name, level_of, severity_of
from .confidence import CONFIDENCE_VERSION
from .result import DetectionHit, Evidence
from .engine import SensitiveDetectionEngine, build_engine, text_matches, ENGINE_VERSION

__all__ = [
    "SensitiveDetectionContext",
    "SensitiveDetectionEngine",
    "DetectionHit",
    "Evidence",
    "build_engine",
    "text_matches",
    "canonical_entity",
    "legacy_name",
    "level_of",
    "severity_of",
    "ENGINE_VERSION",
    "CONFIDENCE_VERSION",
]
