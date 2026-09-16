"""Versioned, centralised confidence.

Confidence is *derived*, never asserted: a rule contributes its precision, a
validator may confirm or weaken it, and repeated evidence for the same span from
the same source never inflates the score - the strongest single observation wins.
"""
from __future__ import annotations

from typing import Iterable

# Bump when the maths below changes so stored findings stay explainable.
CONFIDENCE_VERSION = "1.0.0"

# Evidence kinds, strongest first. Used for documentation and reporting only.
EVIDENCE_TYPES = ("validator", "regex", "keyword", "field_name", "context")

# A field name alone never proves a value; it only makes a column worth checking.
FIELD_EVIDENCE_CEILING = 0.5
# "Low confidence" band for field/context-only types such as name or address.
FIELD_ONLY_CONFIDENCE = 0.35
# Context words ("身份证" next to a number) are weaker than a validator.
CONTEXT_BOOST = 0.1


def clamp(value: float) -> float:
    return round(min(1.0, max(0.0, float(value))), 4)


def combine(confidences: Iterable[float]) -> float:
    """Strongest single observation, ignoring duplicates and order."""
    best = 0.0
    for value in confidences:
        best = max(best, clamp(value))
    return best


def with_context(confidence: float, boosted: bool) -> float:
    return clamp(confidence + CONTEXT_BOOST) if boosted else clamp(confidence)


def field_confidence(rule_confidence: float) -> float:
    return clamp(min(rule_confidence, FIELD_EVIDENCE_CEILING))
