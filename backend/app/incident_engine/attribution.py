"""Recover an incident's asset attribution from the findings it already stored.

Incidents are derived rows: ``IncidentEngine.correlate`` builds them out of
``DetectionFinding`` evidence. Rows written before the asset label was
normalised carry labels such as ``192.168.191.168:192.168.191.168:telnet:23``
(no asset page can ever match that) or ``global`` (the host was only named
inside ``src``/``dst`` or a ``metrics`` key, which the old reader ignored).

Re-deriving the label from the incident's own findings restores the link without
inventing evidence: every address comes from a finding the pipeline really
produced. ``fingerprint`` is deliberately left untouched, so no incident is
duplicated and no alert is renumbered.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engine.core.result import DetectionResult
from app.incident_engine.engine import IncidentEngine, _stage, evidence_asset_keys, evidence_ioc_keys
from app.models import Incident

#: Rows whose label never pointed at a host are counted separately so an
#: operator can tell "repaired" apart from "genuinely global".
GLOBAL_LABEL = "global"


def _stored_findings(row: Incident) -> list[dict[str, Any]]:
    findings = row.findings if isinstance(row.findings, dict) else {}
    items = findings.get("items")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _as_result(item: dict[str, Any]) -> DetectionResult:
    def number(key: str) -> float:
        try:
            return float(item.get(key) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    evidence = item.get("evidence")
    return DetectionResult(
        engine=str(item.get("engine") or ""),
        rule_id=str(item.get("rule_id") or ""),
        severity=str(item.get("severity") or "Low"),
        confidence=number("confidence"),
        evidence=evidence if isinstance(evidence, dict) else {},
        recommendation=str(item.get("recommendation") or ""),
        timestamp=str(item.get("timestamp") or ""),
        risk_score=number("risk_score"),
        risk_level=str(item.get("risk_level") or "Low"),
    )


def rebuild_attribution(db: Session) -> dict[str, Any]:
    """Re-derive every incident's hosts from its stored findings."""
    engine = IncidentEngine()
    scanned = relabelled = recovered = unattributed = 0
    globals_before = globals_after = 0
    hosts: set[str] = set()
    sample: list[dict[str, str]] = []
    for row in db.scalars(select(Incident).order_by(Incident.id)).all():
        scanned += 1
        evidence = row.evidence if isinstance(row.evidence, dict) else {}
        previous = str(evidence.get("asset") or "")
        if previous == GLOBAL_LABEL:
            globals_before += 1
        results = [_as_result(item) for item in _stored_findings(row)]
        assets = sorted({value for item in results for value in evidence_asset_keys(item.evidence)})
        if not assets:
            unattributed += 1
            globals_after += previous in ("", GLOBAL_LABEL)
            continue
        hosts.update(assets)
        iocs = sorted({value for item in results for value in evidence_ioc_keys(item.evidence)})
        ioc = iocs[0] if iocs else ""
        updated = dict(evidence)
        updated["asset"] = assets[0]
        updated["assets"] = assets
        updated["stages"] = sorted({_stage(item) for item in results})
        if ioc:
            updated["ioc"] = ioc
        if updated != evidence:
            relabelled += 1
        if previous != assets[0]:
            recovered += 1
            row.title = engine._title(results, assets[0], ioc)[:255]
            if len(sample) < 10:
                sample.append({"id": str(row.id), "from": previous or "(empty)", "to": assets[0]})
        row.evidence = updated
    db.flush()
    return {
        "scanned": scanned,
        "recovered": recovered,
        "relabelled": relabelled,
        "unattributed": unattributed,
        "globals_before": globals_before,
        "globals_after": globals_after,
        "hosts": len(hosts),
        "sample": sample,
    }


__all__ = ["rebuild_attribution", "GLOBAL_LABEL"]
