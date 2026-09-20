# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Detection findings and analysis-result domain.

The HTTP boundary only: the rows are produced by the detection engines and the
worker pipeline; this module owns the list filters, pagination and the response
shape the console reads.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.incident_presenter import serialize_incident
from app.api.pagination import page_response, paginate
from app.api.pcaps import serialize_pcap
from app.api.query_filters import string_time_filter
from app.core.database import get_db
from app.models import Alert, AnalysisResult, DetectionFinding, Incident, PcapRecord
from app.services.alert_service import serialize_alert

router = APIRouter()


@router.get("/analysis/results")
def analysis_results(
    module: str | None = None, db: Session = Depends(get_db)
) -> list[dict[str, Any]]:
    query = select(AnalysisResult)
    if module:
        query = query.where(AnalysisResult.module == module)
    return [
        {
            "id": item.id,
            "task_id": item.task_id,
            "module": item.module,
            "content": item.content,
            "score": item.score,
            "risk_level": item.risk_level,
            "created_at": item.created_at,
        }
        for item in db.scalars(query.order_by(AnalysisResult.id.desc())).all()
    ]


@router.get("/detections")
def list_detections(
    severity: str | None = None,
    engine: str | None = None,
    risk_level: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    search: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(DetectionFinding)
    if severity:
        query = query.where(DetectionFinding.severity == severity)
    if engine:
        query = query.where(DetectionFinding.engine == engine)
    if risk_level:
        query = query.where(DetectionFinding.risk_level == risk_level)
    if target_type:
        query = query.where(DetectionFinding.target_type == target_type)
    if target_id:
        query = query.where(DetectionFinding.target_id == target_id)
    if search:
        query = query.where(
            or_(
                DetectionFinding.rule_id.ilike(f"%{search}%"),
                DetectionFinding.engine.ilike(f"%{search}%"),
                DetectionFinding.recommendation.ilike(f"%{search}%"),
            )
        )
    query = string_time_filter(query, DetectionFinding.timestamp, start_time, end_time)
    result = paginate(db, query.order_by(DetectionFinding.risk_score.desc()), page, page_size)
    return page_response(
        [_serialize_detection(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/detections/{detection_id}")
def detection_detail(detection_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(DetectionFinding, detection_id)
    if not item:
        raise HTTPException(404, "detection not found")
    incidents = db.scalars(
        select(Incident).where(Incident.findings["items"].as_string().ilike(f"%{item.rule_id}%"))
    ).all()
    pcap = (
        db.get(PcapRecord, int(item.target_id))
        if item.target_type == "pcap" and str(item.target_id).isdigit()
        else None
    )
    alert = db.scalar(select(Alert).where(Alert.finding_id == item.id))
    return {
        "detection": _serialize_detection(item),
        "related_incidents": [serialize_incident(item) for item in incidents],
        "pcap": serialize_pcap(pcap) if pcap else None,
        "alert": serialize_alert(alert) if alert else None,
    }
