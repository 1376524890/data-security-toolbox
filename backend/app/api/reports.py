# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Reporting domain: audit summaries, log analysis and generated reports.

The HTTP boundary only: ``services/audit_service.py`` and
``services/report_service.py`` build the content; this module owns the paths,
pagination and the stored-report download.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.assets import serialize_asset
from app.api.data_assets import _serialize_data_asset as _serialize_data_asset
from app.api.files import serialize_file
from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.incident_presenter import serialize_incident
from app.api.pagination import page_response, paginate
from app.api.pcaps import serialize_anomaly, serialize_pcap
from app.core.config import settings
from app.core.database import get_db
from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.risk_engine.engine import RiskEngine
from app.models import (
    Anomaly,
    Asset,
    DataAsset,
    DetectionFinding,
    FileRecord,
    Incident,
    PcapRecord,
    Report,
)
from app.schemas import GenerateReportRequest, LogAnalysisRequest
from app.services.audit_service import audit_summary, log_analysis
from app.services.report_service import build_summary, render_html, render_pdf

router = APIRouter()


def serialize_report(item: Report) -> dict[str, Any]:
    path = Path(item.storage_path)
    return {
        "id": item.id,
        "title": item.title,
        "report_type": item.report_type,
        "format": item.format,
        "summary": item.summary,
        "storage_path": item.storage_path,
        "size": path.stat().st_size if path.exists() else 0,
        "created_at": item.created_at,
    }


@router.post("/audit/logs")
def analyze_log(payload: LogAnalysisRequest) -> dict[str, Any]:
    lines = payload.content.splitlines()
    context = DetectionContext(target_type="log", data={}, log_lines=lines)
    pipeline = DetectionPipeline(registry, RiskEngine())
    result = pipeline.run(context)
    return {
        "log_summary": log_analysis(lines),
        "findings": [item.to_dict() for item in result.findings],
        "risk": {"score": result.risk_score, "level": result.risk_level},
    }


@router.get("/audit/summary")
def audit(db: Session = Depends(get_db)) -> dict[str, Any]:
    assets = [serialize_asset(item) for item in db.scalars(select(Asset)).all()]
    files = [serialize_file(item) for item in db.scalars(select(FileRecord)).all()]
    pcaps = [serialize_pcap(item) for item in db.scalars(select(PcapRecord)).all()]
    anomalies = [serialize_anomaly(item) for item in db.scalars(select(Anomaly)).all()]
    return audit_summary(assets, files, pcaps, anomalies)


@router.post("/reports/generate")
def generate_report(
    payload: GenerateReportRequest, db: Session = Depends(get_db)
) -> dict[str, Any]:
    assets = [serialize_asset(item) for item in db.scalars(select(Asset)).all()]
    files = [serialize_file(item) for item in db.scalars(select(FileRecord)).all()]
    pcaps = [serialize_pcap(item) for item in db.scalars(select(PcapRecord)).all()]
    anomalies = [serialize_anomaly(item) for item in db.scalars(select(Anomaly)).all()]
    findings = [
        _serialize_detection(item)
        for item in db.scalars(
            select(DetectionFinding).order_by(DetectionFinding.risk_score.desc())
        ).all()
    ]
    data_assets = [
        _serialize_data_asset(item)
        for item in db.scalars(select(DataAsset).order_by(DataAsset.id.desc())).all()
    ]
    incidents = [
        serialize_incident(item)
        for item in db.scalars(select(Incident).order_by(Incident.risk_score.desc())).all()
    ]
    summary = build_summary(
        assets,
        files,
        pcaps,
        anomalies,
        audit_summary(assets, files, pcaps, anomalies),
        findings,
        data_assets,
        incidents,
    )
    html = render_html(summary, assets, files, pcaps, anomalies, findings, data_assets, incidents)
    report_format = payload.format
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    output = settings.report_dir / f"{payload.title.replace(' ', '_')}_{stamp}.{report_format}"
    if report_format == "pdf":
        try:
            render_pdf(html, output)
        except ImportError:
            report_format = "html"
            output = output.with_suffix(".html")
            output.write_text(html, encoding="utf-8")
    else:
        output.write_text(html, encoding="utf-8")
    record = Report(
        title=payload.title,
        report_type=payload.report_type,
        format=report_format,
        storage_path=str(output),
        summary=summary,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return serialize_report(record)


@router.get("/reports")
def list_reports(
    report_type: str | None = None,
    format: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(Report)
    if report_type:
        query = query.where(Report.report_type == report_type)
    if format:
        query = query.where(Report.format == format)
    if search:
        query = query.where(Report.title.ilike(f"%{search}%"))
    result = paginate(db, query.order_by(Report.id.desc()), page, page_size)
    return page_response(
        [serialize_report(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)) -> FileResponse:
    item = db.get(Report, report_id)
    if not item:
        raise HTTPException(404, "report not found")
    path = Path(item.storage_path)
    if not path.exists():
        raise HTTPException(404, "report file not found")
    return FileResponse(str(path), filename=path.name)
