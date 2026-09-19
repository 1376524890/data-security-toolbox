"""Cross-domain analysis and correlation orchestration.

The pipeline run, incident upsert and alert fan-out used to live inside the
Celery task module; they are domain work that both HTTP (re-correlate endpoints)
and the workers need, so they live here and never import ``app.workers``.

Transactions stay with the caller: ``run_pipeline`` commits only when it owns
the session it created.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.core.database import SessionLocal
from app.domain.evidence_identity import evidence_asset_keys
from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.core.result import DetectionResult
from app.engine.graph import build_graph
from app.engine.risk_engine.engine import RiskEngine
from app.incident_engine.engine import IncidentEngine
from app.models import IOC, Alert, DataAsset, DetectionFinding, GraphRelation, Incident, LocalCve
from app.services.alert_service import (
    EVENT_CREATED,
    EVENT_UPDATED,
    create_finding_alert,
    create_incident_alert,
    publish_alert,
    queue_deliveries,
)
from app.services.task_dispatch import DELIVER_ALERT, dispatch

pipeline = DetectionPipeline(registry, RiskEngine())
incident_engine = IncidentEngine()


def _capture_exposure(flows: list[dict[str, Any]]) -> tuple[float, str]:
    """Exposure factor derived from the capture's own destination evidence.

    Importing a PCAP used to set ``exposure_factor = 3`` for every capture, which
    pushed High/0.8 findings across the notification threshold with no evidence.
    The neutral default is 2.0 (RiskEngine divides by two), raised only when the
    capture actually talks to a public destination. The basis travels with the
    score so an operator can see why it moved.
    """
    import ipaddress

    destinations = {str(flow.get("dst_ip") or "") for flow in flows}
    destinations.discard("")
    if not destinations:
        return 2.0, "unknown"
    for value in destinations:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return 3.0, "external_destination"
        if not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        ):
            return 3.0, "external_destination"
    return 2.0, "internal_only"


def _recent_findings(
    db,
    probe_id: int | None,
    window_seconds: int = 3600,
    exclude_task_id: int | None = None,
) -> list[DetectionResult]:
    since = datetime.now(UTC) - timedelta(seconds=window_seconds)
    query = select(DetectionFinding).where(DetectionFinding.created_at >= since)
    if exclude_task_id is not None:
        query = query.where(DetectionFinding.task_id != exclude_task_id)
    rows = db.scalars(query.order_by(DetectionFinding.timestamp).limit(10000)).all()
    # A superseded run is history: it must not keep re-announcing a live incident.
    rows = [item for item in rows if not (item.evidence or {}).get("superseded")]
    if probe_id is not None:
        rows = [
            item
            for item in rows
            if int((item.evidence or {}).get("probe_id") or 0) == int(probe_id)
        ]
    return [
        DetectionResult(
            engine=item.engine,
            rule_id=item.rule_id,
            severity=item.severity,
            confidence=item.confidence,
            evidence=item.evidence,
            recommendation=item.recommendation,
            timestamp=item.timestamp,
            risk_score=item.risk_score,
            risk_level=item.risk_level,
        )
        for item in rows
    ]


def _finding_signature(item: dict[str, Any]) -> str:
    evidence = item.get("evidence") or {}
    # Findings are plain dicts at this point, so the identity is rebuilt with
    # the same rules the incident engine uses. Reading only src_ip/dst_ip/asset
    # left every traffic finding (which spells them ``src``/``dst``) on an
    # empty asset and merged distinct hosts into one signature.
    assets = ",".join(evidence_asset_keys(evidence))
    return f"{item.get('engine')}|{item.get('rule_id')}|{item.get('timestamp')}|{assets}"


def _merge_findings(
    existing: list[dict[str, Any]],
    incoming: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in [*existing, *incoming]:
        if isinstance(item, dict):
            merged.setdefault(_finding_signature(item), item)
    return list(merged.values())


def _upsert_incident(db, incident: Incident, probe_id: int | None) -> Incident:
    existing = db.scalar(select(Incident).where(Incident.fingerprint == incident.fingerprint))
    now = datetime.now(UTC)
    if existing:
        merged = _merge_findings((existing.findings or {}).get("items", []), incident.findings)
        existing.findings = {"items": merged}
        existing.evidence = {**(existing.evidence or {}), **incident.evidence}
        existing.risk_score = max(existing.risk_score, incident.risk_score)
        existing.risk_level = incident.risk_level
        existing.severity = incident.severity if existing.severity != "Critical" else "Critical"
        existing.last_seen = now
        existing.occurrence_count += 1
        existing.probe_id = probe_id or existing.probe_id
        return existing
    row = Incident(
        fingerprint=incident.fingerprint,
        probe_id=probe_id,
        source=incident.source,
        title=(incident.title or "")[:255],
        severity=incident.severity,
        confidence=incident.confidence,
        status=incident.status,
        findings={"items": incident.findings},
        evidence=incident.evidence,
        risk_score=incident.risk_score,
        risk_level=incident.risk_level,
        timestamp=incident.timestamp,
        last_seen=now,
        occurrence_count=1,
    )
    db.add(row)
    db.flush()
    return row


def _run_correlations_and_alerts(
    db,
    context: DetectionContext,
    task_id: int,
    result,
    probe_id: int | None,
) -> list[tuple[Alert, bool]]:
    persisted: list[DetectionFinding] = []
    for finding in result.findings:
        row = DetectionFinding(
            task_id=task_id,
            target_type=context.target_type,
            target_id=str(context.target_id or ""),
            engine=finding.engine,
            rule_id=finding.rule_id,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence={**finding.evidence, "probe_id": probe_id},
            recommendation=finding.recommendation,
            risk_score=finding.risk_score,
            risk_level=finding.risk_level,
            timestamp=finding.timestamp,
        )
        db.add(row)
        persisted.append(row)
    db.flush()
    # Historical findings must NOT include the current task (avoids the current
    # finding being counted twice). Current findings are appended exactly once.
    historical = _recent_findings(db, probe_id, 3600, exclude_task_id=task_id)
    historical.extend(
        DetectionResult(
            engine=item.engine,
            rule_id=item.rule_id,
            severity=item.severity,
            confidence=item.confidence,
            evidence=item.evidence,
            recommendation=item.recommendation,
            timestamp=item.timestamp,
            risk_score=item.risk_score,
            risk_level=item.risk_level,
        )
        for item in persisted
    )
    incidents = incident_engine.correlate(historical, 3600)
    alerts: list[tuple[Alert, bool]] = []
    for incident in incidents:
        if context.target_type == "pcap":
            incident.evidence["pcap_id"] = str(context.target_id or "")
        row = _upsert_incident(db, incident, probe_id)
        alert, created = create_incident_alert(db, row)
        if alert:
            alerts.append((alert, created))
    for finding in persisted:
        alert, created = create_finding_alert(db, finding, probe_id)
        if alert:
            alerts.append((alert, created))
    # Deduplicate by alert id, preferring ``created=True`` when any path is new.
    deduped: dict[int, tuple[Alert, bool]] = {}
    for alert, created in alerts:
        prev = deduped.get(alert.id)
        if prev is None or created:
            deduped[alert.id] = (alert, created)
    return list(deduped.values())


def run_pipeline(context: DetectionContext, task_id: int, db=None) -> list[tuple[int, bool]]:
    if db is not None:
        context.data["ioc_library"] = [
            {"value": item.value, "type": item.ioc_type, "source": item.source}
            for item in db.scalars(select(IOC)).all()
            if (item.extra or {}).get("enabled", True)
        ]
        from app.models import SystemSetting
        from app.services.dlp_service import DEFAULT_POLICY

        policy = db.scalar(select(SystemSetting).where(SystemSetting.key == "dlp_policy"))
        context.data["dlp_policy"] = policy.value if policy else DEFAULT_POLICY
        # Grype contains hundreds of thousands of CVEs. Query per service in
        # ThreatIntelEngine rather than loading the whole catalog per packet task.
        if db.scalar(select(LocalCve.id).limit(1)) is not None:
            context.data["cve_lookup_enabled"] = True
        from app.integrations.offline_manager import resolve_active_suricata_rules_dir

        context.data["suricata_rules_dir"] = resolve_active_suricata_rules_dir(db)
    result = pipeline.run(context)
    owned = db is None
    session = db or SessionLocal()
    probe_id = context.data.get("probe_id")
    try:
        alerts = _run_correlations_and_alerts(session, context, task_id, result, probe_id)
        for alert, _created in alerts:
            queue_deliveries(session, alert.id)
        for item in context.data.get("iocs", []):
            if not isinstance(item, dict):
                continue
            session.add(
                IOC(
                    ioc_type=item.get("type", item.get("ioc_type", "unknown")),
                    value=item.get("value", ""),
                    source=item.get("source", "integration"),
                    first_seen=item.get("first_seen", ""),
                    last_seen=item.get("last_seen", ""),
                    tags=item.get("tags", []),
                    extra=item,
                )
            )
        for item in context.data.get("data_assets", []):
            session.add(
                DataAsset(
                    name=item.get("name", ""),
                    asset_type=item.get("asset_type", "file"),
                    sensitivity=item.get("sensitivity", "Low"),
                    source=item.get("source", "file"),
                    columns=item.get("columns", []),
                    extra=item.get("extra", {}),
                )
            )
        relations = build_graph(
            context.assets,
            context.data.get("data_assets", []),
            [item.to_dict() for item in result.findings],
        )
        for relation in relations:
            session.add(GraphRelation(**relation))
        if owned:
            session.commit()
            for alert, created in alerts:
                publish_alert(alert.id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
                dispatch(DELIVER_ALERT, alert.id)
            return [(alert.id, created) for alert, created in alerts]
        return [(alert.id, created) for alert, created in alerts]
    finally:
        if owned:
            session.close()


# Public names: the analysis entry points are called by the API and the workers.
run_correlations_and_alerts = _run_correlations_and_alerts
upsert_incident = _upsert_incident
recent_findings = _recent_findings
capture_exposure = _capture_exposure
