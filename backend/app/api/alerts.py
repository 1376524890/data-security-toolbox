# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Alert domain: triage queue, live stream and alert detail.

The HTTP boundary only: suppression, delivery and hit aggregation stay in
``services/alert_service.py``; this module owns the paths, filters and the
response shape the console reads.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.assets import serialize_asset
from app.api.data_assets import _serialize_data_asset as _serialize_data_asset
from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.incident_presenter import serialize_incident
from app.api.ioc_presenter import serialize_ioc
from app.api.pagination import page_response, paginate
from app.api.pcaps import serialize_pcap
from app.api.probe_presenter import serialize_probe
from app.api.rule_presenter import rule_definition
from app.core.config import settings
from app.core.database import get_db
from app.incident_engine.engine import evidence_asset_keys, evidence_primary_asset
from app.models import (
    IOC,
    Alert,
    AlertDelivery,
    Asset,
    DataAsset,
    DetectionFinding,
    Incident,
    PcapRecord,
    Probe,
)
from app.services.alert_service import (
    event_type_for_status,
    list_alert_hits,
    publish_alert,
    serialize_alert,
)

router = APIRouter()


@router.get("/alerts")
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    probe_id: int | None = None,
    start: str | None = None,
    end: str | None = None,
    search: str | None = None,
    order: str = Query("risk", pattern="^(risk|recent)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(Alert)
    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    if source:
        query = query.where(Alert.source == source)
    if probe_id:
        query = query.where(Alert.probe_id == probe_id)
    if start:
        query = query.where(Alert.created_at >= start)
    if end:
        query = query.where(Alert.created_at <= end)
    if search:
        query = query.where(
            or_(Alert.title.ilike(f"%{search}%"), Alert.summary.ilike(f"%{search}%"))
        )
    # ``risk`` is the console's default (worst first). The 数据安全态势大屏 needs
    # the newest rows instead, because "实时安全事件" means time order; keeping it
    # a parameter avoids a second list route that would drift from this one.
    if order == "recent":
        ordered = query.order_by(Alert.last_seen.desc(), Alert.id.desc())
    else:
        ordered = query.order_by(Alert.risk_score.desc(), Alert.last_seen.desc())
    result = paginate(db, ordered, page, page_size)
    return page_response(
        [serialize_alert(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/alerts/summary")
def alert_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    status_rows = db.execute(
        select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
    ).all()
    severity_rows = db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    ).all()
    unhandled = (
        db.scalar(
            select(func.count(Alert.id)).where(
                Alert.status == "new", Alert.severity.in_(["Critical", "High"])
            )
        )
        or 0
    )
    return {
        "total": db.scalar(select(func.count(Alert.id))) or 0,
        "status": {status: count for status, count in status_rows},
        "severity": {severity: count for severity, count in severity_rows},
        "unhandled_critical_high": unhandled,
    }


@router.get("/alerts/stream")
def alert_stream(request: Request) -> StreamingResponse:
    import redis as redis_lib

    def event_source():
        client = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True)
        pubsub = client.pubsub()
        pubsub.subscribe("security.alerts")
        try:
            yield "event: ping\ndata: connected\n\n"
            for message in pubsub.listen():
                if message.get("type") != "message":
                    continue
                yield f"event: alert\ndata: {message['data']}\n\n"
        finally:
            pubsub.close()
            client.close()

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "alert not found")
    finding = db.get(DetectionFinding, alert.finding_id) if alert.finding_id else None
    incident = db.get(Incident, alert.incident_id) if alert.incident_id else None
    probe = db.get(Probe, alert.probe_id) if alert.probe_id else None
    pcap = None
    if finding and finding.target_type == "pcap":
        pcap = (
            db.get(PcapRecord, int(finding.target_id)) if str(finding.target_id).isdigit() else None
        )
    deliveries = db.scalars(
        select(AlertDelivery)
        .where(AlertDelivery.alert_id == alert.id)
        .order_by(AlertDelivery.id.desc())
    ).all()
    # Derive associated assets / IOC / data assets from the finding evidence.
    assets: list[dict[str, Any]] = []
    iocs: list[dict[str, Any]] = []
    data_assets: list[dict[str, Any]] = []
    if finding:
        evidence = finding.evidence or {}
        # Shared resolver first, then every other address the evidence names, so
        # the detail view and the incident engine agree on the subject.
        candidate_ips: list[str] = []
        primary = evidence_primary_asset(evidence)
        if primary:
            candidate_ips.append(primary)
        candidate_ips.extend(
            key for key in evidence_asset_keys(evidence) if key not in candidate_ips
        )
        candidate_iocs: list[str] = []
        for key in ("value", "query", "qname", "rrname", "domain", "url", "uri", "ioc"):
            value = evidence.get(key)
            if isinstance(value, str) and value not in candidate_iocs:
                candidate_iocs.append(value)
            elif isinstance(value, dict) and value.get("value"):
                candidate_iocs.append(str(value["value"]))
        if candidate_ips:
            asset_rows = db.scalars(
                select(Asset).where(Asset.ip.in_(candidate_ips)).limit(50)
            ).all()
            assets = [serialize_asset(item) for item in asset_rows]
        if candidate_iocs:
            ioc_rows = db.scalars(select(IOC).where(IOC.value.in_(candidate_iocs)).limit(50)).all()
            iocs = [serialize_ioc(item) for item in ioc_rows]
        file_name = evidence.get("file") or (
            evidence.get("record", {}).get("filename")
            if isinstance(evidence.get("record"), dict)
            else ""
        )
        if file_name:
            da_rows = db.scalars(
                select(DataAsset).where(DataAsset.name == file_name).limit(50)
            ).all()
            data_assets = [_serialize_data_asset(item) for item in da_rows]
    return {
        "alert": serialize_alert(alert),
        "finding": _serialize_detection(finding) if finding else None,
        # The authored rule behind this alert, so the console can show what
        # matched instead of only the rule id.
        "rule": (
            rule_definition(db, finding.rule_id, finding.engine, finding.evidence)
            if finding
            else None
        ),
        "incident": serialize_incident(incident) if incident else None,
        "probe": serialize_probe(probe) if probe else None,
        "pcap": serialize_pcap(pcap) if pcap else None,
        "assets": assets,
        "iocs": iocs,
        "data_assets": data_assets,
        "deliveries": [
            {
                "id": item.id,
                "channel": item.channel,
                "target": item.target,
                "status": item.status,
                "attempts": item.attempts,
                "last_error": item.last_error,
                "sent_at": item.sent_at,
            }
            for item in deliveries
        ],
        # Suppression keeps one live alert per subject; these rows keep every
        # observation behind it, with the first / latest / highest-risk flagged.
        "hits": list_alert_hits(db, alert.id),
    }


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: int, payload: dict[str, Any], db: Session = Depends(get_db)
) -> dict[str, Any]:
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "alert not found")
    status = payload.get("status")
    if status:
        if status not in {"new", "acknowledged", "resolved", "suppressed"}:
            raise HTTPException(400, "invalid alert status")
        alert.status = status
    if "severity" in payload:
        alert.severity = str(payload["severity"])
    if "summary" in payload:
        alert.summary = str(payload["summary"])
    alert.last_seen = datetime.now(UTC)
    db.commit()
    db.refresh(alert)
    publish_alert(alert.id, event_type=event_type_for_status(alert.status))
    return serialize_alert(alert)
