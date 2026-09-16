"""The engine itself: one implementation for probe and platform.

Usage::

    engine = build_engine()
    for hit in engine.scan_text(text, field_name="phone"):
        ...

The engine never returns, stores or logs a matched value. It reports how many
distinct spans matched, which rules produced evidence and how confident that
evidence is.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from . import confidence as confidence_module
from . import matching
from .context import SensitiveDetectionContext
from .entities import canonical_entity, level_of
from .result import DetectionHit, Evidence
from .rules import builtin_rules, normalize_rule
from .validators import get_validator

ENGINE_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"

# Field evidence is only a hint, so it never exceeds the evidence ceiling.
FIELD_EVIDENCE_CEILING = confidence_module.FIELD_EVIDENCE_CEILING


@dataclass(slots=True)
class ScanReport:
    """Engine bookkeeping. Carries no text and no matched value."""

    engine_version: str = ENGINE_VERSION
    rules_evaluated: int = 0
    rules_skipped: list[dict[str, str]] = field(default_factory=list)
    timeouts: list[str] = field(default_factory=list)
    truncated: bool = False
    text_truncated: bool = False
    backend: str = matching.REGEX_BACKEND

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine_version": self.engine_version,
            "rules_evaluated": self.rules_evaluated,
            "rule_errors": list(self.rules_skipped),
            "rule_timeouts": list(self.timeouts),
            "truncated": self.truncated,
            "text_truncated": self.text_truncated,
            "regex_backend": self.backend,
        }


class SensitiveDetectionEngine:
    """Rule-driven sensitive-data detection with bounded work per call."""

    def __init__(self, rules: Iterable[dict[str, Any]] | None = None, *,
                 max_text_chars: int = matching.MAX_TEXT_CHARS,
                 timeout: float = matching.DEFAULT_TIMEOUT,
                 max_matches: int = matching.MAX_MATCHES_PER_RULE) -> None:
        self.timeout = timeout
        self.max_matches = max_matches
        self.max_text_chars = max_text_chars
        self.rules: list[dict[str, Any]] = []
        self.rule_errors: list[dict[str, str]] = []
        for raw in (rules if rules is not None else builtin_rules()):
            self.add_rule(raw)
        self.last_report = ScanReport()

    # -- rule management ----------------------------------------------------
    def add_rule(self, raw: dict[str, Any]) -> bool:
        """Validate and register one rule. A broken rule is skipped, never fatal."""
        rule = normalize_rule(raw)
        rule_id = str(rule.get("rule_id") or "")
        entity = canonical_entity(rule.get("entity"))
        pattern = str(rule.get("pattern") or "")
        if not rule_id:
            self.rule_errors.append({"rule_id": "", "reason": "missing_rule_id"})
            return False
        if len(self.rules) >= matching.MAX_PATTERNS:
            self.rule_errors.append({"rule_id": rule_id, "reason": "too_many_rules"})
            return False
        if pattern:
            if len(pattern) > matching.MAX_PATTERN_CHARS:
                self.rule_errors.append({"rule_id": rule_id, "reason": "pattern_too_long"})
                return False
            if matching.matches_empty(pattern):
                self.rule_errors.append({"rule_id": rule_id, "reason": "matches_empty_string"})
                return False
        validator = str(rule.get("validator") or "")
        if validator and get_validator(validator) is None:
            self.rule_errors.append({"rule_id": rule_id, "reason": f"unknown_validator:{validator}"})
            return False
        rule["entity"] = entity
        rule["level"] = str(rule.get("level") or level_of(entity))
        self.rules.append(rule)
        return True

    @property
    def entities(self) -> list[str]:
        seen: list[str] = []
        for rule in self.rules:
            if rule["entity"] not in seen:
                seen.append(rule["entity"])
        return seen

    def rule_pattern(self, rule: dict[str, Any]) -> Any:
        """Compiled pattern for a registered rule (validated when it was added)."""
        return matching.compile_pattern(str(rule.get("pattern") or ""))

    def capabilities(self) -> dict[str, Any]:
        return {
            "sensitive_detection_v2": True,
            "engine_version": ENGINE_VERSION,
            "schema_version": SCHEMA_VERSION,
            "regex_backend": matching.REGEX_BACKEND,
            "regex_timeout": matching.SUPPORTS_TIMEOUT,
            "rule_count": len(self.rules),
            "entities": self.entities,
        }

    # -- scanning -----------------------------------------------------------
    def scan(self, context: SensitiveDetectionContext) -> list[DetectionHit]:
        text = context.text or ""
        text_truncated = False
        if len(text) > self.max_text_chars:
            text = text[: self.max_text_chars]
            text_truncated = True
        field_name = (context.field_name or "").strip().lower()
        lowered = text.casefold()
        intervals: dict[str, list[tuple[int, int]]] = {}
        evidence: dict[str, list[Evidence]] = {}
        report = ScanReport(truncated=False, text_truncated=text_truncated,
                            rules_skipped=list(self.rule_errors))
        report.rules_evaluated = len(self.rules)

        def add(entity: str, item: Evidence) -> None:
            evidence.setdefault(entity, [])
            key = (item.rule_id, item.evidence_type, item.rule_source)
            if any((existing.rule_id, existing.evidence_type, existing.rule_source) == key
                   for existing in evidence[entity]):
                return
            evidence[entity].append(item)

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            entity = rule["entity"]
            rule_id = rule["rule_id"]
            source = str(rule.get("rule_source") or "builtin")
            recognizer = str(rule.get("recognizer") or "")
            rule_confidence = confidence_module.clamp(rule.get("confidence") or 0.5)
            field_hit = bool(field_name) and any(hint in field_name for hint in rule["field_hints"])
            keyword_hit = bool(text) and any(keyword in lowered for keyword in rule["keywords"])
            if rule["pattern"]:
                try:
                    scan = matching.matches(rule["pattern"], text, self.timeout, self.max_matches)
                except matching.PatternError as exc:
                    report.rules_skipped.append({"rule_id": rule_id, "reason": str(exc)[:64]})
                    continue
                report.timeouts.extend(scan.timeouts)
                report.truncated = report.truncated or scan.truncated
                if scan.intervals:
                    validator = get_validator(rule.get("validator"))
                    kept: list[tuple[int, int]] = []
                    validator_facts: dict[str, Any] = {}
                    validator_confidence: float | None = None
                    for interval in scan.intervals:
                        if validator is None:
                            kept.append(interval)
                            continue
                        outcome = validator(text[interval[0]:interval[1]])
                        if not outcome.accepted:
                            continue
                        kept.append(interval)
                        if outcome.confidence is not None:
                            validator_confidence = max(validator_confidence or 0.0, outcome.confidence)
                        if outcome.facts:
                            validator_facts.update(outcome.facts)
                    if kept:
                        intervals.setdefault(entity, []).extend(kept)
                        effective = validator_confidence if validator_confidence is not None else rule_confidence
                        add(entity, Evidence(
                            rule_id=rule_id, entity=entity, recognizer=recognizer,
                            evidence_type="validator" if validator_confidence is not None else "regex",
                            confidence=confidence_module.with_context(effective, field_hit),
                            rule_source=source, facts=validator_facts,
                        ))
            if keyword_hit:
                add(entity, Evidence(rule_id=rule_id, entity=entity, recognizer=recognizer,
                                     evidence_type="keyword",
                                     confidence=confidence_module.field_confidence(rule_confidence),
                                     rule_source=source))
            if field_hit:
                add(entity, Evidence(rule_id=rule_id, entity=entity, recognizer=recognizer,
                                     evidence_type="field_name",
                                     confidence=confidence_module.field_confidence(rule_confidence),
                                     rule_source=source))

        hits: list[DetectionHit] = []
        for entity, items in evidence.items():
            merged = matching.merge_intervals(intervals.get(entity, []))
            hit = DetectionHit(entity=entity, source_entity=entity, count=len(merged),
                               evidence=items, context_evidence=not merged)
            hits.append(hit)
        # Strongest first; structural metadata last so real data leads the report.
        hits.sort(key=lambda item: (item.sensitive, item.confidence, item.count), reverse=True)
        report.timeouts = list(dict.fromkeys(report.timeouts))
        self.last_report = report
        return hits

    def scan_text(self, text: str, **context: Any) -> list[DetectionHit]:
        return self.scan(SensitiveDetectionContext(text=text or "", **context))

    def scan_field(self, field_name: str, **context: Any) -> list[DetectionHit]:
        """Field-name-only detection (used for Excel/CSV headers)."""
        return self.scan(SensitiveDetectionContext(field_name=field_name or "", **context))


def build_engine(rules: Iterable[dict[str, Any]] | None = None, **kwargs: Any) -> SensitiveDetectionEngine:
    return SensitiveDetectionEngine(rules, **kwargs)
