"""Detection results.

Neither :class:`Evidence` nor :class:`DetectionHit` can hold a matched value:
there is no field for one, so "the report carries no raw value" is enforced by
the data structure rather than by remembering to mask a string.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import confidence as confidence_module
from .entities import canonical_entity, is_field_only, is_structural, level_of, severity_of

# Rule provenance. A static import must never look like a live recognizer run.
RULE_SOURCES = ("builtin", "manual", "presidio_static", "presidio_runtime")


@dataclass(slots=True)
class Evidence:
    """Why a hit exists. ``facts`` may only carry non-identifying booleans/counts."""

    rule_id: str
    entity: str
    recognizer: str = ""
    evidence_type: str = "regex"
    confidence: float = 0.0
    rule_source: str = "builtin"
    facts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "rule_id": self.rule_id,
            "entity": self.entity,
            "evidence_type": self.evidence_type,
            "confidence": confidence_module.clamp(self.confidence),
            "rule_source": self.rule_source,
        }
        if self.recognizer:
            payload["recognizer"] = self.recognizer
        if self.facts:
            payload["facts"] = dict(self.facts)
        return payload


@dataclass(slots=True)
class DetectionHit:
    """One sensitive type found in one context, with deduplicated evidence."""

    entity: str
    source_entity: str = ""
    count: int = 0
    confidence: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)
    context_evidence: bool = False

    def __post_init__(self) -> None:
        self.entity = canonical_entity(self.entity)
        self.source_entity = self.source_entity or self.entity
        self.count = max(0, int(self.count))
        self.confidence = confidence_module.combine([item.confidence for item in self.evidence]) or confidence_module.clamp(self.confidence)

    @property
    def sensitive(self) -> bool:
        """Structural metadata is reported but can never make data sensitive."""
        return not is_structural(self.entity)

    @property
    def confirmed(self) -> bool:
        """Value-level evidence exists (a regex/validator span, not only a hint).

        A header name, a keyword or a context word is a *candidate*: it says the
        column is worth checking, not that personal data was found. Callers that
        raise an alert or label a file must use this, so an empty CSV whose only
        signal is a ``phone`` header is not reported as discovered PII.
        """
        return (self.sensitive and self.count > 0 and not self.context_evidence
                and self.confidence >= confidence_module.CONFIRMED_CONFIDENCE)

    @property
    def field_only(self) -> bool:
        """True when P0 has no value-level evidence for this type (no NER)."""
        return is_field_only(self.entity)

    @property
    def level(self) -> str:
        return level_of(self.entity)

    @property
    def severity(self) -> str:
        return severity_of(self.entity)

    @property
    def rule_ids(self) -> list[str]:
        seen: list[str] = []
        for item in self.evidence:
            if item.rule_id not in seen:
                seen.append(item.rule_id)
        return seen

    @property
    def rule_sources(self) -> list[str]:
        seen: list[str] = []
        for item in self.evidence:
            if item.rule_source not in seen:
                seen.append(item.rule_source)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "source_entity": self.source_entity,
            "count": self.count,
            "confidence": self.confidence,
            "sensitive": self.sensitive,
            "field_only": self.field_only,
            "level": self.level,
            "severity": self.severity,
            "evidence": [item.to_dict() for item in self.evidence],
        }
