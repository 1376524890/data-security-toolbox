"""Document-type signals read from recognised text and page layout.

OCR hands the platform text it could never read before - a scanned 公文, a
photographed 红头文件 - and this module turns that text plus the page's colour
layout into named, explainable signals: is this an official red-header document,
and does it carry a 密级 (secrecy) marking? The findings the data engine raises
are built from these signals, so the classifier stays pure text plus a couple of
colour ratios: no file content, no dependencies, and nothing it cannot explain.

Two deliberate limits:

* it *names signals*, it does not decide a document is secret. A red banner and
  a "秘密" in a novel are both real strings, so level markings require the
  standard ``密级``/``★`` shape or two independent secrecy markers, and a
  red-header claim requires the layout band to agree with the text.
* the evidence is the matched phrase itself, so an operator can open the page and
  check what fired instead of trusting a score.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Signal kinds. The data engine maps these to findings one-to-one.
SIGNAL_CLASSIFIED = "classified_document"
SIGNAL_RED_HEADER = "red_header_document"
SIGNAL_OFFICIAL = "official_document"
SIGNAL_SEAL = "seal"

#: Chinese secrecy levels, highest first. ``涉密`` is the generic ("this is a
#: classified matter") wording and carries no level of its own.
LEVELS = ("绝密", "机密", "秘密")
_LEVEL_SEVERITY = {"绝密": "Critical", "机密": "Critical", "秘密": "High"}
_GENERIC_SEVERITY = "High"

# ``机密★10年`` / ``秘密★长期`` - the standard marking shape.
_STAR_MARKING = re.compile(r"(绝密|机密|秘密)\s*[★☆*]\s*(?:长期|\d{1,3}\s*年)?")
# ``密级：机密`` - the labelled form used in headers and forms.
_LABELLED_MARKING = re.compile(r"密级\s*[:：]?\s*(绝密|机密|秘密)")
# Words that only appear around a real secrecy marking.
_SECRECY_MARKERS = re.compile(r"国家秘密|涉密|保密期限|知悉范围|保密守则|密级")
_BARE_LEVEL = re.compile(r"绝密|机密|秘密")

# 发文字号, e.g. ``国办发〔2023〕12号`` - the strongest official-document marker.
_DOC_NUMBER = re.compile(r"[〔\[（(【]\s*\d{4}\s*[〕\]）)】]\s*第?\s*\d{1,5}\s*号")
# A standalone title line ending in 文件, e.g. ``国务院办公厅文件``.
_TITLE_FILE = re.compile(r"^.{0,30}文\s*件\s*$", re.MULTILINE)
# ``关于……的通知`` and friends.
_OFFICIAL_HEADING = re.compile(
    r"关于.{0,40}的(?:通知|决定|批复|报告|请示|意见|函|公告|通告|命令|纪要|议案|规定|办法)"
)
# Issuing agencies and the 成文日期 that close a 公文.
_ISSUING_AGENCY = re.compile(r"人民政府|国务院|办公厅|委员会|党组|党委|人民代表大会")
_DOC_DATE = re.compile(r"\d{4}\s*年\s*\d{1,2}\s*月\s*\d{1,2}\s*日")
_SEAL_TEXT = re.compile(r"（盖章）|\(盖章\)|印章")


@dataclass(frozen=True, slots=True)
class DocumentSignal:
    """One explainable reason to call a document a 红头/涉密/公文."""

    kind: str
    label: str
    severity: str
    confidence: float
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "label": self.label,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "evidence": list(self.evidence),
        }


def _first(matches: list[str], fallback: str = "") -> str:
    return matches[0] if matches else fallback


def _highest_level(levels: list[str]) -> str:
    for level in LEVELS:
        if level in levels:
            return level
    return ""


def _classified(text: str) -> list[DocumentSignal]:
    """A 密级 marking, or two independent words that only co-occur in one."""
    marked = [match.group(1) for match in _STAR_MARKING.finditer(text)]
    marked += [match.group(1) for match in _LABELLED_MARKING.finditer(text)]
    raw = [match.group(0) for match in _STAR_MARKING.finditer(text)]
    raw += [match.group(0) for match in _LABELLED_MARKING.finditer(text)]
    markers = [match.group(0) for match in _SECRECY_MARKERS.finditer(text)]
    bare = [match.group(0) for match in _BARE_LEVEL.finditer(text)]

    if marked:
        level = _highest_level(marked)
        confidence = 0.9
    elif len(markers) >= 2:
        # "涉密载体 / 保密期限" with no level word is still a classified matter.
        level = ""
        confidence = 0.6
    elif markers and bare:
        level = _highest_level(bare)
        confidence = 0.5
    else:
        return []

    severity = _LEVEL_SEVERITY.get(level, _GENERIC_SEVERITY)
    label = f"涉密文件（{level}）" if level else "涉密文件"
    evidence = list(dict.fromkeys(raw + markers + bare))[:8]
    return [DocumentSignal(kind=SIGNAL_CLASSIFIED, label=label, severity=severity,
                           confidence=confidence, evidence=evidence)]


def _official(text: str, layout: dict) -> list[DocumentSignal]:
    """红头文件 / 公文, from the layout band agreeing with the text markers."""
    band = bool(layout.get("red_title_band"))
    doc_number = [match.group(0) for match in _DOC_NUMBER.finditer(text)]
    title = [match.group(0).strip() for match in _TITLE_FILE.finditer(text)]
    heading = [match.group(0) for match in _OFFICIAL_HEADING.finditer(text)]
    agency = [match.group(0) for match in _ISSUING_AGENCY.finditer(text)]
    date = [match.group(0) for match in _DOC_DATE.finditer(text)]

    evidence = list(dict.fromkeys(doc_number + title + heading + agency + date))[:8]
    strong = bool(doc_number or title)
    weak = len(heading) + len(agency) + len(date)

    if band and (strong or weak):
        return [DocumentSignal(kind=SIGNAL_RED_HEADER, label="红头文件（公文）",
                               severity="Medium", confidence=0.85, evidence=evidence)]
    if band:
        # A red band alone is a letterhead, not yet a 公文.
        return [DocumentSignal(kind=SIGNAL_RED_HEADER, label="红头版式文件",
                               severity="Low", confidence=0.5, evidence=evidence)]
    if strong:
        return [DocumentSignal(kind=SIGNAL_OFFICIAL, label="公文",
                               severity="Medium", confidence=0.7, evidence=evidence)]
    if weak >= 2:
        return [DocumentSignal(kind=SIGNAL_OFFICIAL, label="疑似公文",
                               severity="Low", confidence=0.5, evidence=evidence)]
    return []


def _seal(text: str, layout: dict) -> list[DocumentSignal]:
    """A red seal on the page or an explicit 盖章 placeholder."""
    hits = [match.group(0) for match in _SEAL_TEXT.finditer(text)]
    if not layout.get("red_seal") and not hits:
        return []
    return [DocumentSignal(kind=SIGNAL_SEAL, label="印章", severity="Low",
                           confidence=0.6 if layout.get("red_seal") else 0.5,
                           evidence=hits[:4])]


def classify(text: str, layout: dict | None = None) -> list[DocumentSignal]:
    """Signals for one document's recognised text plus its page layout.

    ``layout`` is what :func:`shared.scanning.ocr.analyze_layout` returns, or
    empty when only the text layer was available - a text-layer PDF carries the
    markings but not the colours, and every signal stays explainable either way.
    """
    layout = layout or {}
    body = text or ""
    if not body.strip() and not layout:
        return []
    signals: list[DocumentSignal] = []
    if body.strip():
        signals += _classified(body)
        signals += _official(body, layout)
        signals += _seal(body, layout)
    else:
        signals += _seal(body, layout)
    return signals


def strongest(signals: list[DocumentSignal],
             kinds: set[str] | None = None) -> DocumentSignal | None:
    """The highest-severity signal, optionally restricted to ``kinds``."""
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    candidates = [item for item in signals if kinds is None or item.kind in kinds]
    if not candidates:
        return None
    return max(candidates, key=lambda item: (severity_rank.get(item.severity, 0), item.confidence))
