"""Re-deriving a report's confidence instead of trusting the number it carries.

A probe states, per category, how sure *its* rule set was: a Presidio recognizer
that scores itself 0.6, or a rule the probe downloaded months ago and still
reports at the score it was shipped with. The platform must not take that number
on trust -- an over-matching pattern that scored itself 0.6 is exactly how 331
Swedish organisation numbers were raised as findings, and an old probe keeps
claiming its old score even after the rule behind it was tightened.

So the only question asked at ingest is: *would the rules the platform scans with
today raise this?* The evidence a row carries names its rule (``rule_id``) and the
kind of proof it is (``evidence_type``); the rule's precision is looked up in the
live engine and the confidence is derived from that, not from the payload.

Nothing is inferred. A rule the platform no longer holds, or a category that
carried no evidence at all, is *not* proof that a value is wrong: those keep
whatever the report said, because losing a rule is not the same as finding a
mistake.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.services import sensitive_engine

#: Proof about a *value*. Everything else (``keyword``, ``field_name``, a context
#: word) says a column is worth checking and can never confirm on its own.
VALUE_EVIDENCE_TYPES = frozenset({"regex", "validator"})

_RULES: tuple[tuple, dict[str, dict[str, Any]]] | None = None


def current_rules() -> dict[str, dict[str, Any]]:
    """Every rule the platform scans with right now, by rule id.

    Cached on the rule store's own signature, the same way
    :func:`sensitive_engine.scan_engine` caches its engine, so a rule edit is
    picked up at once and a report of a thousand entries does not stat the store
    a thousand times.
    """
    global _RULES
    signature = sensitive_engine.analyst_signature()
    if _RULES is not None and _RULES[0] == signature:
        return _RULES[1]
    index = {
        str(rule.get("rule_id")): rule
        for rule in sensitive_engine.scan_engine().rules
        if rule.get("rule_id")
    }
    _RULES = (signature, index)
    return index


def confirm_threshold() -> float:
    """The confidence at or above which a value-level hit is a finding."""
    from shared.sensitive_detection.confidence import CONFIRMED_CONFIDENCE

    return CONFIRMED_CONFIDENCE


def confidence_for(rule: dict[str, Any], evidence_type: Any) -> float:
    """One rule's precision for one kind of evidence.

    A regex or a validator carries the rule's own precision. A header name or a
    keyword does not: it is capped by the shared field-evidence ceiling, which is
    below the confirm threshold, so a column that is merely *named* ``phone`` is
    never presented as a column that *contains* one.
    """
    from shared.sensitive_detection.confidence import clamp, field_confidence

    confidence = float(rule.get("confidence") or 0.0)
    if str(evidence_type or "") not in VALUE_EVIDENCE_TYPES:
        return field_confidence(confidence)
    return clamp(confidence)


def derived_confidence(
    category: str, evidence_rows: Iterable[dict[str, Any]]
) -> float | None:
    """What the platform's own rules say about one category, or ``None``.

    ``None`` means there was nothing to judge: no evidence rows, or every row
    named a rule this platform no longer has. The caller keeps the reported score
    in that case, which is also why a payload cannot evade the gate by omitting
    its rule ids -- it can only lose the right to be re-derived, and the rules it
    cannot name are not rules this platform would have run.
    """
    rules = current_rules()
    best: float | None = None
    for row in evidence_rows:
        if row.get("category") != category:
            continue
        rule = rules.get(str(row.get("rule_id") or ""))
        if rule is None:
            continue
        value = confidence_for(rule, row.get("evidence_type"))
        best = value if best is None else max(best, value)
    return best


def is_confirmed(confidence: float | None) -> bool:
    """True when a derived confidence would raise a finding at all."""
    return confidence is not None and confidence >= confirm_threshold()


def demoted_categories(
    categories: Iterable[str], evidence_rows: Iterable[dict[str, Any]]
) -> list[str]:
    """Categories the platform's rules would not raise, in the order given.

    Used to move a report's own claim into the candidate list instead of
    dropping it: the operator still sees *that* a number looked like an
    organisation number, it just stops being counted as discovered data.
    """
    rows = list(evidence_rows)
    weak: list[str] = []
    for category in categories:
        confidence = derived_confidence(category, rows)
        if confidence is not None and confidence < confirm_threshold():
            weak.append(category)
    return weak
