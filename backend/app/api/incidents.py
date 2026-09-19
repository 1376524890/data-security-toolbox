# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Incident and indicator domain: correlation, triage and IOC associations.

The HTTP boundary only: correlation itself stays in ``incident_engine`` and the
row shapes come from the shared presenters, so this module owns the paths,
filters and response assembly for incidents and IOCs.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.assets import serialize_asset
from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.incident_presenter import serialize_incident
from app.api.ioc_presenter import serialize_ioc
from app.api.pagination import page_response, paginate
from app.api.query_filters import string_time_filter as _string_time_filter
from app.core.database import get_db
from app.incident_engine.engine import IncidentEngine
from app.models import IOC, Asset, DetectionFinding, Incident

router = APIRouter()
incident_engine = IncidentEngine()


@router.get("/incidents")
def list_incidents(
    severity: str | None = None,
    status: str | None = None,
    search: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(Incident)
    if severity:
        query = query.where(Incident.severity == severity)
    if status:
        query = query.where(Incident.status == status)
    if search:
        query = query.where(
            or_(
                Incident.title.ilike(f"%{search}%"),
                Incident.evidence["asset"].as_string().ilike(f"%{search}%"),
                Incident.evidence["ioc"].as_string().ilike(f"%{search}%"),
            )
        )
    query = _string_time_filter(query, Incident.timestamp, start_time, end_time)
    result = paginate(
        db, query.order_by(Incident.risk_score.desc(), Incident.timestamp.desc()), page, page_size
    )
    return page_response(
        [serialize_incident(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(Incident, incident_id)
    if not item:
        raise HTTPException(404, "incident not found")
    return serialize_incident(item)


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int, payload: dict[str, Any], db: Session = Depends(get_db)
) -> dict[str, Any]:
    item = db.get(Incident, incident_id)
    if not item:
        raise HTTPException(404, "incident not found")
    for key in ("status", "severity", "title"):
        if key in payload:
            setattr(item, key, payload[key])
    db.commit()
    db.refresh(item)
    return serialize_incident(item)


@router.post("/incidents/correlate")
def correlate_incidents(payload: dict[str, Any]) -> list[dict[str, Any]]:
    from app.engine.core.result import DetectionResult

    findings = [DetectionResult(**item) for item in payload.get("findings", [])]
    return [
        item.to_dict()
        for item in incident_engine.correlate(findings, int(payload.get("window_seconds", 3600)))
    ]


@router.post("/incidents/rebuild-attribution")
def rebuild_incident_attribution(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Re-derive each incident's hosts from the findings that incident stored.

    Repairs rows written before the asset label was normalised. Derived fields
    only: no incident is created, deleted or re-fingerprinted.
    """
    from app.incident_engine.attribution import rebuild_attribution
    from app.services.audit_service import record_audit

    result = rebuild_attribution(db)
    record_audit(
        db, request, action="incidents.rebuild_attribution", target="incidents", details=result
    )
    db.commit()
    return result


@router.get("/iocs")
def list_iocs(
    ioc_type: str | None = None,
    source: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(IOC)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if source:
        query = query.where(IOC.source == source)
    if search:
        query = query.where(IOC.value.ilike(f"%{search}%"))
    result = paginate(db, query.order_by(IOC.id.desc()), page, page_size)
    return page_response(
        [serialize_ioc(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/iocs/{ioc_id}/associations")
def ioc_associations(ioc_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(IOC, ioc_id)
    if not item:
        raise HTTPException(404, "ioc not found")
    findings = db.scalars(
        select(DetectionFinding)
        .where(DetectionFinding.evidence["value"].as_string() == item.value)
        .order_by(DetectionFinding.risk_score.desc())
    ).all()
    incidents = db.scalars(
        select(Incident)
        .where(Incident.evidence["ioc"].as_string() == item.value)
        .order_by(Incident.risk_score.desc())
    ).all()
    assets = db.scalars(
        select(Asset).where(or_(Asset.ip == item.value, Asset.hostname == item.value))
    ).all()
    return {
        "ioc": serialize_ioc(item),
        "findings": [_serialize_detection(item) for item in findings],
        "incidents": [serialize_incident(item) for item in incidents],
        "assets": [serialize_asset(item) for item in assets],
    }
