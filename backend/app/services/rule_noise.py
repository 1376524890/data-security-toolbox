"""Which rule is doing the talking, and how much of it is worth hearing.

A rule store can be judged before it is trusted. This reads only rows that
already exist and answers, per rule: how many findings has it raised, how many of
those fed an alert, and would the platform's own reading of the rule raise them
again today? The last question is the one that matters after a false-positive
sweep -- a rule with thousands of rows and a confidence below the confirm
threshold is the reason the sweep existed.

``replay`` is the dry run for the other direction: given a rule, re-test the原文
already stored against it, as it stands now, validators included. Nothing is
written, so an operator can see what a rule would do to the history they already
have before deciding to switch it on.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, AlertHit, DetectionEvidence, DetectionFinding
from app.services import detection_gate, sensitive_engine
from app.services.finding_hygiene import _validator, _values

#: A rule's history is bounded like everything else here: a report of how a rule
#: behaves needs a sample, not the entire table.
MAX_REPLAY_ROWS = 2000


def _rule_entry(rule: dict[str, Any] | None) -> dict[str, Any]:
    """One rule's identity in this report; an unknown rule is said to be unknown.

    ``known_rule`` is not decoration: the traffic and YARA rules alert without ever
    passing through the sensitivity rule store, so "the platform has no *data*
    rule by this id" is a different statement from "this rule cannot alert", and
    ``alertable`` stays ``None`` rather than guessing at the second one.
    """
    if rule is None:
        return {"name": "", "source": "", "entity": "", "pattern": "",
                "platform_confidence": None, "alertable": None, "known_rule": False}
    confidence = float(rule.get("confidence") or 0.0)
    return {
        "name": str(rule.get("name") or ""),
        "source": str(rule.get("rule_source") or rule.get("source") or ""),
        "entity": str(rule.get("entity") or ""),
        "pattern": str(rule.get("pattern") or ""),
        "platform_confidence": confidence,
        "alertable": detection_gate.is_confirmed(confidence),
        "known_rule": True,
    }


def noise_report(db: Session, *, limit: int = 200) -> dict[str, Any]:
    """Per-rule volume, on both the data and the finding side."""
    rules = detection_gate.current_rules()
    items: dict[str, dict[str, Any]] = {}

    def slot(rule_id: str) -> dict[str, Any]:
        entry = items.get(rule_id)
        if entry is None:
            entry = {"rule_id": rule_id, "detections": 0, "evidence_rows": 0,
                     "unconfirmable_rows": 0, "findings": 0, "alerts": 0,
                     **_rule_entry(rules.get(rule_id))}
            items[rule_id] = entry
        return entry

    rows = db.execute(
        select(
            DetectionEvidence.rule_id,
            DetectionEvidence.evidence_type,
            func.count(DetectionEvidence.id),
            func.count(func.distinct(DetectionEvidence.detection_id)),
        ).group_by(DetectionEvidence.rule_id, DetectionEvidence.evidence_type)
    ).all()
    for rule_id, evidence_type, evidence_rows, detections in rows:
        entry = slot(str(rule_id or ""))
        entry["evidence_rows"] += int(evidence_rows)
        entry["detections"] += int(detections)
        rule = rules.get(str(rule_id or ""))
        confidence = (
            detection_gate.confidence_for(rule, evidence_type) if rule is not None else None
        )
        if not detection_gate.is_confirmed(confidence):
            # ``None`` counts here: evidence that cannot name a rule this platform
            # has is evidence it cannot vouch for.
            entry["unconfirmable_rows"] += int(evidence_rows)

    for rule_id, findings in db.execute(
        select(DetectionFinding.rule_id, func.count(DetectionFinding.id)).group_by(
            DetectionFinding.rule_id
        )
    ).all():
        slot(str(rule_id or ""))["findings"] += int(findings)
    for rule_id, alerts in db.execute(
        select(DetectionFinding.rule_id, func.count(AlertHit.id))
        .join(AlertHit, AlertHit.finding_id == DetectionFinding.id)
        .join(Alert, Alert.id == AlertHit.alert_id)
        .group_by(DetectionFinding.rule_id)
    ).all():
        slot(str(rule_id or ""))["alerts"] += int(alerts)

    for entry in items.values():
        rows_seen = entry["evidence_rows"] + entry["findings"]
        entry["noise_ratio"] = (
            round(entry["unconfirmable_rows"] / rows_seen, 4) if rows_seen else 0.0
        )
    ordered = sorted(
        items.values(),
        key=lambda entry: (entry["alerts"], entry["unconfirmable_rows"], entry["evidence_rows"]),
        reverse=True,
    )
    return {
        "items": ordered[:limit],
        "total": len(ordered),
        "confirm_threshold": detection_gate.confirm_threshold(),
        "rules_known": len(rules),
    }


def replay(db: Session, rule_id: str, *, limit: int = MAX_REPLAY_ROWS) -> dict[str, Any] | None:
    """Re-test the原文 already stored for one rule against the rule as it is now.

    ``None`` when the platform does not hold the rule. The result is a dry run:
    nothing is written, so "0 of 40" is a statement about a rule that only ever
    fired on noise, not a change to any finding.
    """
    rule = detection_gate.current_rules().get(rule_id)
    if rule is None:
        return None
    pattern = str(rule.get("pattern") or "")
    alertable = detection_gate.is_confirmed(float(rule.get("confidence") or 0.0))
    if not pattern:
        return {"rule_id": rule_id, "tested": 0, "matched": 0, "timeouts": 0,
                "alertable": alertable,
                "note": "规则没有正则，只能作为字段/上下文证据"}
    compiled = sensitive_engine.compiled_pattern(rule)
    validator = _validator(str(rule.get("validator") or ""))
    tested = matched = timeouts = 0
    for evidence in db.scalars(
        select(DetectionEvidence).where(DetectionEvidence.rule_id == rule_id).limit(limit)
    ):
        for value in _values(evidence):
            tested += 1
            try:
                if not compiled.search(value):
                    continue
            except TimeoutError:
                timeouts += 1
                continue
            if validator is not None and not validator(value).accepted:
                continue
            matched += 1
    return {
        "rule_id": rule_id,
        "tested": tested,
        "matched": matched,
        "timeouts": timeouts,
        "alertable": alertable,
        "note": "回放是对已存原文的只读重放，不修改任何发现",
    }
