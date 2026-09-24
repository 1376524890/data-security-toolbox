# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Integration adapters and offline resource imports.

Two related HTTP surfaces live here: the third-party adapter catalogue with its
manual analysis trigger (``/integrations*``), and the offline resource imports an
air-gapped deployment depends on (``/offline*``: bundle resources, manually
entered CVEs and the asynchronous Grype vulnerability-database jobs).

The HTTP boundary only. Adapter metadata and execution come from
``app.integrations`` (registry, runner) and the offline bundle diffing from
``app.integrations.offline_manager``; the Grype database itself is maintained by
``services/grype_library.py``, alert creation/delivery by
``services/alert_service.py`` and incident aggregation by ``incident_engine``.
Worker capability and rule-inventory reporting is shared with ``/health``
through ``api/runtime_status.py`` and must not be reimplemented here.

The Grype and CVE maintenance routes keep the historical rule-libraries tag
they were published under, so the generated OpenAPI document is unchanged by
the move.
"""

from __future__ import annotations

import json
import re
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
)
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.list_sort import resolve_order
from app.api.pagination import page_response
from app.api.runtime_status import engine_rule_counts, merge_capability, read_worker_capabilities
from app.application.analysis import upsert_incident
from app.core.config import settings
from app.core.database import SessionLocal, get_db
from app.core.storage import safe_path
from app.engine.core.context import DetectionContext
from app.engine.risk_engine.engine import RiskEngine
from app.incident_engine.engine import IncidentEngine
from app.integrations import integration_registry
from app.integrations.offline_manager import (
    LOCAL_CVE_SORTABLE,
    import_offline_path,
    import_uploaded_offline,
    list_local_cves,
    list_offline_resources,
)
from app.integrations.runner import run_adapter
from app.models import Alert, DetectionFinding, LocalCve
from app.services.alert_service import create_finding_alert, create_incident_alert, publish_alert
from app.services.cve_sync import fingerprints as cve_fingerprints
from app.services.cve_sync import sync as sync_cve_library
from app.services.rule_library import atomic_json

router = APIRouter()
incident_engine = IncidentEngine()


def integration_catalogue() -> list[dict[str, Any]]:
    """The adapter catalogue the console renders, with worker-merged health.

    Extracted from the route so the big screen's KPI band counts the same
    components the engine card lists; two spellings of "集成组件 x/y" on one
    page would be a bug, not a rounding difference.
    """
    entries = list(integration_registry.metadata())
    # The API container may lack the Zeek/Suricata binaries while a live
    # analysis worker reports the capability (published to Redis). Surface the
    # worker's availability so the UI doesn't show a working engine as
    # "unavailable" just because the API container can't run it.
    worker_caps = merge_capability(read_worker_capabilities())
    for entry in entries:
        name = str(entry.get("name", ""))
        if name in {"zeek", "suricata"}:
            cap = worker_caps.get(name)
            if cap and cap.get("available") and not entry.get("healthy"):
                entry["installed"] = True
                entry["healthy"] = True
                entry["runtime_version"] = entry.get("runtime_version") or cap.get("version", "")
                entry["status"] = "ready"
                entry["message"] = "available via analysis worker"
                entry["last_error"] = ""
                entry["worker_available"] = True
                if name == "suricata":
                    entry["rule_count"] = max(
                        entry.get("rule_count") or 0, int(cap.get("rule_count") or 0)
                    )
    sigma_count = engine_rule_counts().get("sigma_log_engine", 0)
    entries.append(
        {
            "name": "sigma",
            "version": "1.0.0",
            "adapter_version": "1.0.0",
            "installed": True,
            "enabled": True,
            "healthy": True,
            "runtime_version": "builtin",
            "supported_types": ["log", "text"],
            "capabilities": ["log_detection"],
            "rule_count": sigma_count,
            "status": "ready",
            "message": "Sigma-style log rule interpreter (built-in)",
            "last_check": datetime.now(UTC).isoformat(),
        }
    )
    return entries


@router.get("/integrations")
def list_integrations() -> list[dict[str, Any]]:
    return integration_catalogue()


@router.post("/integrations/{name}/analyze")
def run_integration(
    name: str, payload: dict[str, Any], db: Session = Depends(get_db)
) -> dict[str, Any]:
    try:
        adapter = integration_registry.get(name)
    except KeyError as exc:
        raise HTTPException(404, "integration not found") from exc
    context = DetectionContext(
        target_type="integration", target_id=name, data=payload.get("context", {})
    )
    result = run_adapter(adapter, payload, context, RiskEngine())
    alerts: list[tuple[Alert, bool]] = []
    for item in result.findings:
        finding = DetectionFinding(
            target_type="integration",
            target_id=name,
            engine=item.engine,
            rule_id=item.rule_id,
            severity=item.severity,
            confidence=item.confidence,
            evidence=item.evidence,
            recommendation=item.recommendation,
            risk_score=item.risk_score,
            risk_level=item.risk_level,
            timestamp=item.timestamp,
        )
        db.add(finding)
        db.flush()
        alert, created = create_finding_alert(db, finding)
        if alert:
            alerts.append((alert, created))
    for incident in incident_engine.correlate(result.findings):
        row = upsert_incident(db, incident, None)
        alert, created = create_incident_alert(db, row)
        if alert:
            alerts.append((alert, created))
    db.commit()
    for alert, created in alerts:
        publish_alert(alert.id, event_type="alert.created" if created else "alert.updated")
    return result.to_dict()


@router.post("/integrations/offline/upload")
async def upload_offline(
    file: UploadFile = File(...),
    resource_type: str | None = Form(None),
    name: str | None = Form(None),
    version: str | None = Form(None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    data = await file.read()
    return import_uploaded_offline(
        db, file.filename or "offline.bundle", data, resource_type, name, version
    ).to_dict()


@router.post("/integrations/offline/import")
def import_offline(payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
    path = payload.get("path", "")
    if not path:
        raise HTTPException(400, "path is required")
    candidate = safe_path(settings.integration_dir, path)
    return import_offline_path(
        db, candidate, payload.get("resource_type"), payload.get("name"), payload.get("version")
    ).to_dict()


@router.get("/offline/resources")
def offline_resources(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return list_offline_resources(db)


@router.get("/offline/cves")
def offline_cves(
    search: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    order_by: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    page: int | None = Query(None, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> Any:
    if order_by:
        resolve_order(order_by, LOCAL_CVE_SORTABLE, default="cvss_score")
    # Keep the legacy array contract for existing integrations.
    if page is None:
        return list_local_cves(db, search or "", limit, severity=severity, source=source,
                               order_by=order_by)
    query = select(func.count()).select_from(LocalCve)
    if search:
        query = query.where(LocalCve.cve_id.ilike(f"%{search}%"))
    if severity:
        query = query.where(LocalCve.severity == severity)
    if source:
        query = query.where(LocalCve.source == source)
    total = db.scalar(query) or 0
    return page_response(
        list_local_cves(db, search or "", page_size, (page - 1) * page_size,
                        severity=severity, source=source, order_by=order_by),
        page, page_size, total,
    )


@router.get("/offline/cves/fingerprints")
def cve_fingerprints_for_update(db: Session = Depends(get_db)) -> dict[str, Any]:
    """The products an online update would query NVD for.

    Returned before the call so the operator sees the scope (and its cost)
    instead of firing an unbounded update at a rate-limited public API.
    """
    return {"fingerprints": cve_fingerprints(db)}


class CveSync(BaseModel):
    #: Empty means "whatever the platform fingerprinted"; the update is
    #: fingerprint-driven, not a full NVD mirror.
    keywords: list[str] = Field(default_factory=list)
    per_fingerprint: int = Field(default=50, ge=1, le=2000)


@router.post("/offline/cves/sync")
def sync_cves(payload: CveSync, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Import CVE rules for the fingerprinted products from the NVD 2.0 API."""
    keywords = [item.strip() for item in payload.keywords if item.strip()]
    return sync_cve_library(db, keywords or None, payload.per_fingerprint)


@router.post("/offline/upload")
async def upload_offline_alt(
    file: UploadFile = File(...),
    resource_type: str | None = Form(None),
    name: str | None = Form(None),
    version: str | None = Form(None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    data = await file.read()
    return import_uploaded_offline(
        db, file.filename or "offline.bundle", data, resource_type, name, version
    ).to_dict()


class CveRule(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    severity: Literal["Critical", "High", "Medium", "Low", "Unknown"] = "Medium"
    cvss_score: float = Field(default=0, ge=0, le=10)
    description: str = Field(min_length=1, max_length=50000)


@router.post("/offline/cves", tags=["rule-libraries"])
def add_cve(payload: CveRule, db: Session = Depends(get_db)):
    existing = db.scalar(select(LocalCve).where(LocalCve.cve_id == payload.cve_id))
    if existing:
        raise HTTPException(409, "CVE 已存在；批量更新请使用 JSON 导入")
    row = LocalCve(
        **{**payload.model_dump(), "description": {"text": payload.description}, "source": "manual"}
    )
    db.add(row)
    db.commit()
    return {"cve_id": row.cve_id}


def job_path(identifier):
    if not re.fullmatch("[a-f0-9]{32}", identifier):
        raise HTTPException(404, "任务不存在")
    return settings.storage_dir / "library_jobs" / (identifier + ".json")


def run_grype_job(identifier, source=None):
    from app.services.grype_library import download_latest, import_database, import_lock

    state = {"id": identifier, "status": "running"}

    def progress(**values):
        state.update(values)
        atomic_json(job_path(identifier), state)

    try:
        with import_lock(), tempfile.TemporaryDirectory(dir=settings.integration_dir) as directory:
            progress(stage="starting")
            metadata = {}
            if source is None:
                source, metadata = download_latest(directory, progress)
            with SessionLocal() as db:
                result = import_database(db, source, metadata, progress)
            progress(status="completed", stage="completed", result=result)
    except Exception as exc:
        progress(status="failed", error=str(exc))
    finally:
        if source and Path(source).parent == settings.storage_dir / "library_uploads":
            Path(source).unlink(missing_ok=True)


@router.post("/offline/grype/update", status_code=202, tags=["rule-libraries"])
def update_grype(background: BackgroundTasks):
    identifier = uuid.uuid4().hex
    state = {"id": identifier, "status": "queued"}
    atomic_json(job_path(identifier), state)
    background.add_task(run_grype_job, identifier)
    return state


@router.post("/offline/grype/import", status_code=202, tags=["rule-libraries"])
def upload_grype(background: BackgroundTasks, file: UploadFile = File(...)):
    from app.services.grype_library import MAX_ARCHIVE

    identifier = uuid.uuid4().hex
    directory = settings.storage_dir / "library_uploads"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / identifier
    try:
        size = 0
        with target.open("wb") as output:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_ARCHIVE:
                    raise HTTPException(
                        413, "上传文件超过 2 GB；支持 .tar.zst / .tar.gz / SQLite DB"
                    )
                output.write(chunk)
        if not size:
            raise HTTPException(422, "文件为空")
    except Exception:
        target.unlink(missing_ok=True)
        raise
    state = {"id": identifier, "status": "queued"}
    atomic_json(job_path(identifier), state)
    background.add_task(run_grype_job, identifier, target)
    return state


@router.get("/offline/grype/jobs/{identifier}", tags=["rule-libraries"])
def grype_job(identifier: str):
    path = job_path(identifier)
    if not path.is_file():
        raise HTTPException(404, "任务不存在")
    return json.loads(path.read_text(encoding="utf-8"))
