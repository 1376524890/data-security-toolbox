from __future__ import annotations

from typing import Any

# Entity names mapped to the finding rules the adapter knows, and the shared rule
# pack that produces each record.
LEGACY_ENTITY_BY_SHARED = {
    "ID_CARD": "CN_ID_CARD",
    "PHONE": "CN_PHONE",
    "BANK_CARD": "BANK_CARD",
    "MEDICAL_RECORD": "MEDICAL_RECORD",
    "CREDENTIAL": "SECRET",
    "API_KEY": "SECRET",
    "TOKEN": "SECRET",
}


def _shared_rules() -> list[dict[str, Any]]:
    from app.services import sensitive_engine

    return sensitive_engine.get_engine().rules


# The patterns live in the shared rule pack only. This module used to keep a
# second copy, which is exactly how the platform and the probe drift apart.
def _shared_patterns() -> dict[str, Any]:
    from app.services import sensitive_engine

    patterns: dict[str, Any] = {}
    for rule in _shared_rules():
        entity = LEGACY_ENTITY_BY_SHARED.get(rule.get("entity"))
        if not entity or not rule.get("pattern"):
            continue
        patterns.setdefault(entity, sensitive_engine.compiled_pattern(rule))
    return patterns


REGEX_RULES = _shared_patterns()


def build_recognizers() -> list[Any]:
    """Presidio recognizers built from the shared pack, one per entity."""
    try:
        from presidio_analyzer import Pattern, PatternRecognizer
    except Exception:
        return []
    grouped: dict[str, list[Any]] = {}
    for rule in _shared_rules():
        entity = LEGACY_ENTITY_BY_SHARED.get(rule.get("entity"))
        if not entity or not rule.get("pattern"):
            continue
        grouped.setdefault(entity, []).append(
            Pattern(name=rule["rule_id"], regex=rule["pattern"], score=float(rule["confidence"])))
    return [PatternRecognizer(supported_entity=entity, patterns=patterns, name=f"shared-{entity}")
            for entity, patterns in grouped.items()]


def fallback_scan(text: str) -> list[dict[str, str]]:
    """Built-in patterns via the shared engine, tagged as a static rule source.

    Returns entity names and scores only. The matched value is intentionally not
    returned: a static regex hit is evidence of a pattern, not a payload copy.
    """
    from app.services import sensitive_engine

    results: list[dict[str, str]] = []
    for hit in sensitive_engine.scan_text(text, source_type="text"):
        entity = LEGACY_ENTITY_BY_SHARED.get(hit.entity)
        if not entity or not hit.count:
            continue
        results.append({
            "entity_type": entity,
            "score": str(hit.confidence),
            "count": str(hit.count),
            "rule_source": "presidio_static",
            "rule_ids": ",".join(hit.rule_ids),
        })
    return results


def presidio_scan(text: str, language: str = "zh") -> list[dict[str, str]]:
    """Runtime recognizers when available, otherwise the built-in static pack.

    The returned records carry ``rule_source`` so a caller can never present a
    static pattern hit as a successful NLP run, and they never carry the matched
    text. ``presidio_status()`` reports why the runtime path was skipped.
    """
    from app.core.config import settings

    if not settings.presidio_enabled:
        _record_status(False, False, "disabled_by_settings")
        return fallback_scan(text)
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except Exception as exc:
        _record_status(False, True, f"dependency_missing:{type(exc).__name__}")
        return fallback_scan(text)
    try:
        provider = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": language, "model_name": "xx_ent_wiki_sm"}]})
        analyzer = AnalyzerEngine(registry_configuration={"recognizers": build_recognizers()}, nlp_engine=provider.create_engine())
        results = analyzer.analyze(text=text, language=language)
    except Exception:
        try:
            analyzer = AnalyzerEngine(registry_configuration={"recognizers": build_recognizers()})
            results = analyzer.analyze(text=text, language="en")
        except Exception as exc:
            _record_status(False, True, f"analyzer_failed:{type(exc).__name__}")
            return fallback_scan(text)
    _record_status(True, True, "")
    return [
        {
            "entity_type": str(item.entity_type),
            "score": str(round(float(item.score), 3)),
            "count": "1",
            "rule_source": "presidio_runtime",
        }
        for item in results
    ]


_STATUS: dict[str, Any] = {"available": False, "enabled": False, "reason": "not_attempted"}


def _record_status(available: bool, enabled: bool, reason: str) -> None:
    _STATUS.update(available=available, enabled=enabled, reason=reason)


def presidio_status() -> dict[str, Any]:
    """Why the runtime path was unavailable - reported, never silently ignored."""
    return dict(_STATUS)
