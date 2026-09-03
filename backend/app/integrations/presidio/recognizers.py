from __future__ import annotations

import re
from typing import Any

CN_ID_CARD = re.compile(r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")
CN_PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
BANK_CARD = re.compile(r"(?<!\d)(?:62|4\d{3}|5[1-5]\d{2})[ -]?(?:\d[ -]?){12,17}(?!\d)")
MEDICAL = re.compile(r"(?i)(病历号|病历|诊断|处方|住院号|patient\s*id|medical\s*record|icd[-_\s]?10)\s*[:：=]?\s*([A-Za-z0-9\-_/]{2,64})")
SECRET = re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:：=]\s*([A-Za-z0-9_\-./+=]{8,})")


REGEX_RULES = {
    "CN_ID_CARD": CN_ID_CARD,
    "CN_PHONE": CN_PHONE,
    "BANK_CARD": BANK_CARD,
    "MEDICAL": MEDICAL,
    "SECRET": SECRET,
}


def build_recognizers() -> list[Any]:
    try:
        from presidio_analyzer import Pattern, PatternRecognizer
    except Exception:
        return []
    patterns = [
        (PatternRecognizer, "CN_ID_CARD", r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)", 0.85),
        (PatternRecognizer, "CN_PHONE", r"(?<!\d)1[3-9]\d{9}(?!\d)", 0.85),
        (PatternRecognizer, "BANK_CARD", r"(?<!\d)(?:62|4\d{3}|5[1-5]\d{2})[ -]?(?:\d[ -]?){12,17}(?!\d)", 0.8),
        (PatternRecognizer, "MEDICAL_RECORD", r"(?i)(病历号|病历|诊断|处方|住院号|patient\s*id|medical\s*record|icd[-_\s]?10)", 0.75),
        (PatternRecognizer, "SECRET", r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:：=]\s*[A-Za-z0-9_\-./+=]{8,}", 0.8),
    ]
    recognizers = []
    for cls, name, regex, score in patterns:
        recognizers.append(cls(supported_entity=name, patterns=[Pattern(name=name, regex=regex, score=score)], name=name))
    return recognizers


def fallback_scan(text: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for entity, pattern in REGEX_RULES.items():
        for match in pattern.finditer(text):
            start, end = match.span()
            value = match.group(0)
            if entity == "MEDICAL" and match.groups():
                value = f"{match.group(1)}:{match.group(2)}"
            results.append({"entity_type": entity, "score": "0.75", "start": str(start), "end": str(end), "text": value})
    return results


def presidio_scan(text: str, language: str = "zh") -> list[dict[str, str]]:
    from app.core.config import settings

    if not settings.presidio_enabled:
        return fallback_scan(text)
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except Exception:
        return fallback_scan(text)
    try:
        provider = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": language, "model_name": "xx_ent_wiki_sm"}]})
        analyzer = AnalyzerEngine(registry_configuration={"recognizers": build_recognizers()}, nlp_engine=provider.create_engine())
        results = analyzer.analyze(text=text, language=language)
    except Exception:
        try:
            analyzer = AnalyzerEngine(registry_configuration={"recognizers": build_recognizers()})
            results = analyzer.analyze(text=text, language="en")
        except Exception:
            return fallback_scan(text)
    return [
        {
            "entity_type": str(item.entity_type),
            "score": str(round(float(item.score), 3)),
            "start": str(item.start),
            "end": str(item.end),
            "text": text[item.start : item.end],
        }
        for item in results
    ]
