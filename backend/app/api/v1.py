from __future__ import annotations

import json
import secrets
import shutil
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.pagination import page_response, paginate
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    clear_admin_cookie,
    create_admin_session,
    ensure_admin,
    get_session_user,
    hash_token,
    require_probe_headers,
    set_admin_cookie,
    verify_password,
    verify_token,
)
from app.core.storage import safe_path, stream_to_storage
from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.risk_engine.engine import RiskEngine
from app.incident_engine.engine import IncidentEngine
from app.integrations import integration_registry
from app.integrations.offline_manager import (
    import_offline_path,
    import_uploaded_offline,
    list_local_cves,
    list_offline_resources,
)
from app.integrations.runner import run_adapter
from app.models import (
    IOC,
    AdminSession,
    Alert,
    AlertDelivery,
    AnalysisResult,
    Anomaly,
    Asset,
    DataAsset,
    DetectionFinding,
    FileRecord,
    Flow,
    GraphRelation,
    Incident,
    PacketRecord,
    PcapRecord,
    Probe,
    Report,
    Task,
    User,
)
from app.schemas import (
    GenerateReportRequest,
    Heartbeat,
    LogAnalysisRequest,
    LoginRequest,
    ProbeRegister,
    TaskCreate,
)
from app.services.alert_service import (
    create_finding_alert,
    create_incident_alert,
    event_type_for_status,
    publish_alert,
    serialize_alert,
)
from app.services.asset_service import asset_relations
from app.services.audit_service import audit_summary, log_analysis
from app.services.protocol_service import protocol_tree
from app.services.report_service import build_summary, render_html, render_pdf
from app.services.traffic_service import (
    detect_anomalies,
    host_behavior,
    protocol_distribution,
    top_n_communication,
    traffic_trend,
)
from app.workers.tasks import (
    _upsert_incident,
    analyze_pcap_task,
    asset_task,
    create_task,
    metadata_task,
)

router = APIRouter(prefix="/api/v1")
incident_engine = IncidentEngine()


def _serialize_task(task: Task) -> dict[str, Any]:
    return {
        "id": task.id,
        "kind": task.kind,
        "status": task.status,
        "progress": task.progress,
        "current_stage": task.current_stage,
        "log": task.log,
        "payload": task.payload,
        "result": task.result,
        "error": task.error,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "finished_at": task.finished_at,
    }


def _serialize_asset(item: Asset) -> dict[str, Any]:
    return {
        "id": item.id,
        "probe_id": item.probe_id,
        "ip": item.ip,
        "hostname": item.hostname,
        "os": item.os,
        "port": item.port,
        "protocol": item.protocol,
        "service": item.service,
        "asset_type": item.asset_type,
        "risk_level": item.risk_level,
        "sensitive_categories": item.sensitive_categories,
        "metadata": item.extra,
        "first_seen": item.first_seen,
        "last_seen": _aware(item.last_seen),
    }


def _serialize_detection(item: DetectionFinding) -> dict[str, Any]:
    return {
        "id": item.id,
        "task_id": item.task_id,
        "target_type": item.target_type,
        "target_id": item.target_id,
        "engine": item.engine,
        "rule_id": item.rule_id,
        "severity": item.severity,
        "confidence": item.confidence,
        "evidence": item.evidence,
        "recommendation": item.recommendation,
        "risk_score": item.risk_score,
        "risk_level": item.risk_level,
        "timestamp": item.timestamp,
        "created_at": item.created_at,
    }


def _serialize_incident(item: Incident) -> dict[str, Any]:
    return {
        "id": item.id,
        "fingerprint": item.fingerprint,
        "probe_id": item.probe_id,
        "source": item.source,
        "title": item.title,
        "severity": item.severity,
        "confidence": item.confidence,
        "status": item.status,
        "findings": item.findings,
        "evidence": item.evidence,
        "risk_score": item.risk_score,
        "risk_level": item.risk_level,
        "timestamp": item.timestamp,
        "last_seen": _aware(item.last_seen),
        "occurrence_count": item.occurrence_count,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def _serialize_ioc(item: IOC) -> dict[str, Any]:
    return {
        "id": item.id,
        "type": item.ioc_type,
        "value": item.value,
        "source": item.source,
        "first_seen": item.first_seen,
        "last_seen": _aware(item.last_seen),
        "tags": item.tags,
        "metadata": item.extra,
        "created_at": item.created_at,
    }


def _serialize_pcap(item: PcapRecord) -> dict[str, Any]:
    return {
        "id": item.id,
        "probe_id": item.probe_id,
        "segment_id": item.segment_id,
        "sequence": item.sequence,
        "capture_interface": item.capture_interface,
        "capture_started_at": item.capture_started_at,
        "capture_finished_at": item.capture_finished_at,
        "ingest_status": item.ingest_status,
        "analysis_status": item.analysis_status,
        "probe_metadata": item.probe_metadata,
        "filename": item.filename,
        "size": item.size,
        "sha256": item.sha256,
        "packet_count": item.packet_count,
        "total_packet_count": item.total_packet_count,
        "indexed_packet_count": item.indexed_packet_count,
        "duration": item.duration,
        "capture_start": item.capture_start,
        "capture_end": item.capture_end,
        "file_type": item.file_type,
        "protocol_summary": item.protocol_summary,
        "status": item.status,
        "retention_status": item.retention_status,
        "created_at": item.created_at,
    }


def _serialize_flow(item: Flow) -> dict[str, Any]:
    return {
        "id": item.id,
        "src_ip": item.src_ip,
        "src_port": item.src_port,
        "dst_ip": item.dst_ip,
        "dst_port": item.dst_port,
        "protocol": item.protocol,
        "app_protocol": item.app_protocol,
        "packets": item.packets,
        "bytes": item.bytes,
        "start_time": item.start_time,
        "end_time": item.end_time,
    }


def _serialize_packet(item: PacketRecord) -> dict[str, Any]:
    return {
        "id": item.id,
        "number": item.number,
        "timestamp": item.timestamp,
        "src_ip": item.src_ip,
        "dst_ip": item.dst_ip,
        "src_port": item.src_port,
        "dst_port": item.dst_port,
        "protocol": item.protocol,
        "length": item.length,
        "info": item.info,
    }


def _serialize_anomaly(item: Anomaly) -> dict[str, Any]:
    return {"id": item.id, "rule": item.rule, "severity": item.severity, "description": item.description, "evidence": item.evidence}


def _serialize_data_asset(item: DataAsset) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "asset_type": item.asset_type,
        "sensitivity": item.sensitivity,
        "source": item.source,
        "columns": item.columns,
        "extra": item.extra,
        "created_at": item.created_at,
    }


def _serialize_file(item: FileRecord) -> dict[str, Any]:
    return {
        "id": item.id,
        "probe_id": item.probe_id,
        "name": item.name,
        "path": item.path,
        "size": item.size,
        "sha256": item.sha256,
        "file_type": item.file_type,
        "metadata_json": item.metadata_json,
        "risk_level": item.risk_level,
        "created_at": item.created_at,
    }


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _serialize_probe(item: Probe) -> dict[str, Any]:
    now = datetime.now(UTC)
    status = item.status
    last_seen = _aware(item.last_seen)
    if last_seen:
        age = (now - last_seen).total_seconds()
        if age > 90:
            status = "offline"
        elif status != "degraded" and age < 90:
            status = "online"
    return {
        "id": item.id,
        "name": item.name,
        "hostname": item.hostname,
        "ip_address": item.ip_address,
        "status": status,
        "last_seen": _aware(item.last_seen),
        "metadata": item.extra,
        "created_at": item.created_at,
    }


def _serialize_report(item: Report) -> dict[str, Any]:
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


def _dispatch(task_id: int, kind: str, func, *args: Any) -> None:
    if settings.app_env == "development":
        func(*args, task_id)
        return
    try:
        func.delay(*args, task_id)
    except Exception:
        func(*args, task_id)


def _upload_probe_id(request: Request, db: Session, form_probe_id: int | None) -> int | None:
    try:
        probe = require_probe_headers(request, db)
        return probe.id if probe else form_probe_id
    except HTTPException:
        if settings.app_env == "production":
            user = get_session_user(db, request)
            if user:
                return form_probe_id
        raise


def _queue_backpressure(db: Session) -> None:
    if settings.app_env == "development":
        return
    pending = db.scalar(select(func.count(Task.id)).where(Task.status == "Pending")) or 0
    oldest = db.scalar(select(func.min(Task.created_at)).where(Task.status == "Pending"))
    oldest_age = (datetime.now(UTC) - oldest).total_seconds() if oldest else 0
    if pending >= settings.queue_pending_max or oldest_age >= settings.queue_oldest_pending_seconds:
        retry = max(5, min(120, int(oldest_age or 5)))
        raise HTTPException(429, "analysis queue is congested; retry later", headers={"Retry-After": str(retry)})


def _string_time_filter(query, column, start_time: str | None, end_time: str | None):
    if start_time:
        query = query.where(column >= start_time)
    if end_time:
        query = query.where(column <= end_time)
    return query


@router.post("/auth/login")
def admin_login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)) -> dict[str, Any]:
    ensure_admin(db)
    user = db.scalar(select(User).where(User.username == payload.username))
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "invalid username or password")
    token = create_admin_session(db, user)
    set_admin_cookie(response, token)
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/auth/logout")
def admin_logout(response: Response, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    token = request.cookies.get(settings.cookie_name)
    if token:
        row = db.scalar(select(AdminSession).where(AdminSession.token_hash == hash_token(token)))
        if row:
            db.delete(row)
            db.commit()
    clear_admin_cookie(response)
    return {"status": "ok"}


@router.get("/auth/me")
def admin_me(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    if settings.app_env != "production":
        user = ensure_admin(db)
        return {"id": user.id, "username": user.username, "role": user.role}
    token = request.cookies.get(settings.cookie_name)
    if not token:
        raise HTTPException(401, "not authenticated")
    row = db.scalar(select(AdminSession).where(AdminSession.token_hash == hash_token(token)))
    if not row:
        raise HTTPException(401, "not authenticated")
    user = db.get(User, row.user_id)
    if not user:
        raise HTTPException(401, "not authenticated")
    return {"id": user.id, "username": user.username, "role": user.role}


def _read_worker_capabilities() -> list[dict[str, Any]]:
    try:
        import redis as redis_lib
        client = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=1, socket_timeout=1)
        keys = list(client.scan_iter("worker:capability:*"))
        items = []
        for key in keys:
            try:
                value = client.get(key)
                if value:
                    items.append(json.loads(value))
            except Exception:
                continue
        return items
    except Exception:
        return []


def _merge_capability(capabilities: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for item in capabilities:
        for tool in ("tshark", "zeek", "suricata"):
            info = item.get(tool) or {}
            if not merged.get(tool):
                merged[tool] = {"available": False, "version": "", "rule_count": 0}
            merged[tool]["available"] = bool(merged[tool]["available"] or info.get("available"))
            merged[tool]["version"] = merged[tool]["version"] or info.get("version", "")
            merged[tool]["rule_count"] = max(merged[tool].get("rule_count", 0), int(info.get("rule_count") or 0))
    return merged


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, Any]:
    redis_ok = False
    try:
        import redis as redis_lib
        redis_ok = bool(redis_lib.Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1).ping())
    except Exception:
        redis_ok = False
    try:
        from app.workers.celery_app import celery_app
        inspect = celery_app.control.inspect(timeout=1)
        active = inspect.active() or {}
        pending = inspect.reserved() or {}
        running = sum(len(items) for items in active.values() if items)
        queued = sum(len(items) for items in pending.values() if items)
        workers = sum(1 for items in active.values() if items is not None)
    except Exception:
        running = 0
        queued = 0
        workers = 0
    oldest = db.scalar(select(func.min(Task.created_at)).where(Task.status.in_(["Pending", "Running"])))
    oldest_age = max(0.0, (datetime.now(UTC) - oldest).total_seconds()) if oldest else 0.0
    storage_bytes = sum(path.stat().st_size for path in settings.storage_dir.rglob("*") if path.is_file())
    probes = db.scalars(select(Probe)).all()
    probe_statuses = {item: 0 for item in ("online", "degraded", "offline", "auth_error")}
    for probe in probes:
        probe_statuses[_serialize_probe(probe)["status"]] = probe_statuses.get(_serialize_probe(probe)["status"], 0) + 1
    capabilities = _read_worker_capabilities()
    # A worker is online only if its Redis capability heartbeat is fresh.
    analysis_worker = "online" if capabilities else "offline"
    if capabilities and any(item["tshark"].get("available") for item in capabilities if isinstance(item.get("tshark"), dict)):
        analysis_worker = "ready"
    merged = _merge_capability(capabilities)
    # Overall status reflects the core API/DB/Redis dependency chain. Analysis
    # worker capability is reported granularly and separately below.
    status = "ok" if redis_ok else "degraded"
    return {
        "status": status,
        "service": settings.app_name,
        "api": "ok",
        "database": "ok",
        "redis": "ok" if redis_ok else "unavailable",
        "celery": {"broker": "ok" if redis_ok else "unavailable", "workers": workers, "running": running, "queued": queued},
        "analysis_worker": analysis_worker,
        "worker_capabilities": capabilities,
        "tshark": merged.get("tshark", {"available": False, "version": ""}),
        "zeek": merged.get("zeek", {"available": False, "version": ""}),
        "suricata": merged.get("suricata", {"available": False, "version": "", "rule_count": 0}),
        "storage_usage_bytes": storage_bytes,
        "storage_max_bytes": settings.pcap_storage_max_gb * 1024 * 1024 * 1024,
        "queue": {"pending": db.scalar(select(func.count(Task.id)).where(Task.status == "Pending")) or 0, "running": running, "oldest_pending_age": oldest_age},
        "probe": {"count": len(probes), **probe_statuses},
    }


@router.post("/probes/register")
def register_probe(payload: ProbeRegister, x_probe_bootstrap_token: str | None = Header(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    if settings.app_env == "production":
        if not settings.probe_bootstrap_token or not x_probe_bootstrap_token:
            raise HTTPException(401, "probe bootstrap token required")
        if not verify_token(x_probe_bootstrap_token, hash_token(settings.probe_bootstrap_token)):
            raise HTTPException(401, "invalid probe bootstrap token")
    probe = db.scalar(select(Probe).where(Probe.name == payload.name))
    token = ""
    rotate = not probe or not probe.token_hash or bool(x_probe_bootstrap_token)
    if not probe:
        probe = Probe(name=payload.name, hostname=payload.hostname, ip_address=payload.ip_address, extra=payload.metadata, status="online")
        db.add(probe)
    else:
        probe.hostname = payload.hostname
        probe.ip_address = payload.ip_address
        probe.extra = payload.metadata
        probe.status = "online"
    if rotate:
        token = secrets.token_urlsafe(32)
        probe.token = ""
        probe.token_hash = hash_token(token)
    probe.last_seen = datetime.now(UTC)
    db.commit()
    db.refresh(probe)
    return {"id": probe.id, "name": probe.name, "token": token}


@router.post("/probes/{probe_id}/heartbeat")
def heartbeat(probe_id: int, payload: Heartbeat, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    authenticated = require_probe_headers(request, db)
    if authenticated and authenticated.id != probe_id:
        raise HTTPException(403, "probe id mismatch")
    probe = db.get(Probe, probe_id)
    if not probe:
        raise HTTPException(404, "probe not found")
    metadata = payload.metadata or {}
    capture_status = str(metadata.get("capture_status") or payload.status)
    probe.status = "degraded" if capture_status == "degraded" else payload.status
    probe.extra = payload.metadata or probe.extra
    probe.last_seen = datetime.now(UTC)
    db.commit()
    return {"status": "ok"}


@router.get("/probes")
def list_probes(status: str | None = None, search: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(Probe)
    if status:
        query = query.where(Probe.status == status)
    if search:
        query = query.where(or_(Probe.name.ilike(f"%{search}%"), Probe.hostname.ilike(f"%{search}%"), Probe.ip_address.ilike(f"%{search}%")))
    result = paginate(db, query.order_by(Probe.id.desc()), page, page_size)
    return page_response([_serialize_probe(item) for item in result["items"]], page, page_size, result["total"])


@router.post("/probes/{probe_id}/analyze")
def analyze_probe_assets(probe_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, "assets", {"probe_id": probe_id})
    _dispatch(task.id, "assets", asset_task, probe_id)
    return _serialize_task(task)


@router.get("/probes/{probe_id}/tasks")
def probe_tasks(probe_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    tasks = db.scalars(select(Task).where(Task.payload["probe_id"].as_integer() == probe_id).order_by(Task.id.desc()).limit(50)).all()
    return [_serialize_task(item) for item in tasks]


@router.get("/assets")
def list_assets(risk: str | None = None, asset_type: str | None = None, ip: str | None = None, hostname: str | None = None, probe_id: int | None = None, search: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(Asset)
    if risk:
        query = query.where(Asset.risk_level == risk)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if ip:
        query = query.where(Asset.ip == ip)
    if hostname:
        query = query.where(Asset.hostname == hostname)
    if probe_id:
        query = query.where(Asset.probe_id == probe_id)
    if search:
        query = query.where(or_(Asset.ip.ilike(f"%{search}%"), Asset.hostname.ilike(f"%{search}%"), Asset.service.ilike(f"%{search}%")))
    result = paginate(db, query.order_by(Asset.id.desc()), page, page_size)
    return page_response([_serialize_asset(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/assets/summary")
def asset_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(Asset.risk_level, func.count(Asset.id)).group_by(Asset.risk_level)).all()
    return {"count": db.scalar(select(func.count(Asset.id))) or 0, "risk": {risk: count for risk, count in rows}}


@router.get("/assets/relations")
def asset_relation_list(db: Session = Depends(get_db)) -> list[dict[str, str]]:
    assets = db.scalars(select(Asset)).all()
    return asset_relations([{"ip": item.ip, "service": item.service, "port": item.port} for item in assets])


@router.get("/assets/{asset_id}")
def asset_detail(asset_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(Asset, asset_id)
    if not item:
        raise HTTPException(404, "asset not found")
    findings = db.scalars(select(DetectionFinding).where(DetectionFinding.evidence["ip"].as_string() == item.ip).order_by(DetectionFinding.risk_score.desc()).limit(100)).all()
    incidents = db.scalars(select(Incident).where(Incident.evidence["asset"].as_string() == item.ip).order_by(Incident.risk_score.desc()).limit(50)).all()
    data_assets = db.scalars(select(DataAsset).where(DataAsset.source == item.hostname).limit(100)).all()
    iocs = db.scalars(select(IOC).where(IOC.value.in_([item.ip, item.hostname])).limit(100)).all()
    relations = db.scalars(select(GraphRelation).where(or_(GraphRelation.source_node == item.ip, GraphRelation.target_node == item.ip))).all()
    return {
        "asset": _serialize_asset(item),
        "findings": [_serialize_detection(item) for item in findings],
        "incidents": [_serialize_incident(item) for item in incidents],
        "data_assets": [_serialize_data_asset(item) for item in data_assets],
        "iocs": [_serialize_ioc(item) for item in iocs],
        "relations": [
            {"source_node": item.source_node, "source_type": item.source_type, "target_node": item.target_node, "target_type": item.target_type, "relation": item.relation, "risk": item.risk}
            for item in relations
        ],
    }


@router.post("/files/upload")
async def upload_file(request: Request, file: UploadFile = File(...), probe_id: int | None = Form(None), metadata_json: str | None = Form(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    probe_id = _upload_probe_id(request, db, probe_id)
    try:
        stored = await stream_to_storage(file, file.filename or "upload.bin", subdir="uploads", max_bytes=settings.max_upload_mb * 1024 * 1024)
    except ValueError as exc:
        if "too_large" in str(exc):
            raise HTTPException(413, "file too large") from exc
        raise
    path = Path(stored["path"])
    record = FileRecord(probe_id=probe_id, name=path.name, path=str(path), size=int(stored["size"]), sha256=str(stored["sha256"]), file_type="", metadata_json=json.loads(metadata_json) if metadata_json else {})
    db.add(record)
    db.commit()
    db.refresh(record)
    task = create_task(db, "metadata", {"file_id": record.id})
    _dispatch(task.id, "metadata", metadata_task, record.id)
    return {"id": record.id, "task_id": task.id, "name": record.name, "size": record.size}


@router.get("/files")
def list_files(search: str | None = None, file_type: str | None = None, risk_level: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(FileRecord)
    if search:
        query = query.where(FileRecord.name.ilike(f"%{search}%"))
    if file_type:
        query = query.where(FileRecord.file_type == file_type)
    if risk_level:
        query = query.where(FileRecord.risk_level == risk_level)
    result = paginate(db, query.order_by(FileRecord.id.desc()), page, page_size)
    return page_response([_serialize_file(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/files/{file_id}")
def file_detail(file_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(FileRecord, file_id)
    if not item:
        raise HTTPException(404, "file not found")
    findings = db.scalars(select(DetectionFinding).where(DetectionFinding.target_type == "file", DetectionFinding.target_id == str(file_id)).order_by(DetectionFinding.risk_score.desc())).all()
    data_assets = db.scalars(select(DataAsset).where(DataAsset.source == item.name)).all()
    return {"file": _serialize_file(item), "findings": [_serialize_detection(item) for item in findings], "data_assets": [_serialize_data_asset(item) for item in data_assets]}


@router.post("/files/{file_id}/analyze")
def analyze_file(file_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, "metadata", {"file_id": file_id})
    _dispatch(task.id, "metadata", metadata_task, file_id)
    return _serialize_task(task)


@router.post("/pcaps/upload")
async def upload_pcap(request: Request, file: UploadFile = File(...), probe_id: int | None = Form(None), metadata_json: str | None = Form(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    probe_id = _upload_probe_id(request, db, probe_id)
    _queue_backpressure(db)
    meta: dict[str, Any] = json.loads(metadata_json) if metadata_json else {}
    try:
        stored = await stream_to_storage(file, file.filename or "capture.pcap", subdir="pcaps", max_bytes=settings.max_upload_mb * 1024 * 1024)
    except ValueError as exc:
        if "too_large" in str(exc):
            raise HTTPException(413, "pcap too large") from exc
        raise
    path = Path(stored["path"])
    digest = str(stored["sha256"])
    segment_id = str(meta.get("segment_id") or digest)
    existing = db.scalar(select(PcapRecord).where(PcapRecord.probe_id == probe_id, PcapRecord.segment_id == segment_id))
    if not existing and not meta.get("segment_id"):
        existing = db.scalar(select(PcapRecord).where(PcapRecord.probe_id == probe_id, PcapRecord.sha256 == digest))
    if existing:
        path.unlink(missing_ok=True)
        return {"id": existing.id, "task_id": None, "filename": existing.filename, "size": existing.size, "duplicate": True}
    record = PcapRecord(
        probe_id=probe_id,
        segment_id=segment_id,
        sequence=int(meta.get("sequence") or 0),
        capture_interface=str(meta.get("interface") or ""),
        capture_started_at=str(meta.get("capture_started_at") or ""),
        capture_finished_at=str(meta.get("capture_finished_at") or ""),
        probe_metadata=meta,
        filename=path.name,
        storage_path=str(path),
        size=int(stored["size"]),
        sha256=digest,
        ingest_status="ingested",
        analysis_status="pending",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    task = create_task(db, "pcap", {"pcap_id": record.id})
    _dispatch(task.id, "pcap", analyze_pcap_task, record.id)
    return {"id": record.id, "task_id": task.id, "filename": record.filename, "size": record.size, "duplicate": False}


@router.get("/pcaps")
def list_pcaps(search: str | None = None, status: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(PcapRecord)
    if search:
        query = query.where(PcapRecord.filename.ilike(f"%{search}%"))
    if status:
        query = query.where(PcapRecord.status == status)
    result = paginate(db, query.order_by(PcapRecord.id.desc()), page, page_size)
    return page_response([_serialize_pcap(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/pcaps/{pcap_id}")
def pcap_detail(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(PcapRecord, pcap_id)
    if not item:
        raise HTTPException(404, "pcap not found")
    return _serialize_pcap(item)


@router.post("/pcaps/{pcap_id}/analyze")
def analyze_pcap(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, "pcap", {"pcap_id": pcap_id})
    _dispatch(task.id, "pcap", analyze_pcap_task, pcap_id)
    return _serialize_task(task)


@router.get("/pcaps/{pcap_id}/flows")
def pcap_flows(pcap_id: int, protocol: str | None = None, ip: str | None = None, port: int | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=5000), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(Flow).where(Flow.pcap_id == pcap_id)
    if protocol:
        query = query.where(Flow.protocol == protocol)
    if ip:
        query = query.where(or_(Flow.src_ip == ip, Flow.dst_ip == ip))
    if port:
        query = query.where(or_(Flow.src_port == port, Flow.dst_port == port))
    result = paginate(db, query.order_by(Flow.bytes.desc()), page, page_size)
    return page_response([_serialize_flow(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/pcaps/{pcap_id}/packets")
def pcap_packets(pcap_id: int, protocol: str | None = None, ip: str | None = None, port: int | None = None, page: int = Query(1, ge=1), page_size: int = Query(100, ge=1, le=5000), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(PacketRecord).where(PacketRecord.pcap_id == pcap_id)
    if protocol:
        query = query.where(PacketRecord.protocol == protocol)
    if ip:
        query = query.where(or_(PacketRecord.src_ip == ip, PacketRecord.dst_ip == ip))
    if port:
        query = query.where(or_(PacketRecord.src_port == port, PacketRecord.dst_port == port))
    result = paginate(db, query.order_by(PacketRecord.number), page, page_size)
    return page_response([_serialize_packet(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/pcaps/{pcap_id}/anomalies")
def pcap_anomalies(pcap_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [_serialize_anomaly(item) for item in db.scalars(select(Anomaly).where(Anomaly.pcap_id == pcap_id).order_by(Anomaly.id.desc())).all()]


@router.get("/pcaps/{pcap_id}/protocols")
def pcap_protocols(pcap_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    item = db.get(PcapRecord, pcap_id)
    if not item:
        raise HTTPException(404, "pcap not found")
    return protocol_tree(item.protocol_summary or {})


@router.get("/pcaps/{pcap_id}/traffic")
def pcap_traffic(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    flows = [_serialize_flow(item) for item in db.scalars(select(Flow).where(Flow.pcap_id == pcap_id)).all()]
    packets = [_serialize_packet(item) for item in db.scalars(select(PacketRecord).where(PacketRecord.pcap_id == pcap_id).order_by(PacketRecord.number)).all()]
    return {
        "trend": traffic_trend(packets),
        "top_n": top_n_communication(flows),
        "protocols": protocol_distribution(flows),
        "hosts": host_behavior(flows, packets),
        "anomalies": detect_anomalies(flows, packets),
    }


def _external_details(pcap_id: int, db: Session) -> dict[str, Any]:
    result = {"dns": [], "http": [], "tls": [], "files": [], "alerts": []}
    rows = db.scalars(select(AnalysisResult).where(AnalysisResult.module == "protocol_details", AnalysisResult.task_id.in_(select(Task.id).where(Task.payload["pcap_id"].as_integer() == pcap_id)))).all()
    for row in rows:
        content = row.content or {}
        result["dns"].extend(content.get("dns", {}).get("queries", []))
        result["http"].extend(content.get("http", {}).get("requests", []))
        result["tls"].extend(content.get("tls", {}).get("handshakes", []))
    external = db.scalars(select(AnalysisResult).where(AnalysisResult.module == "external_engine", AnalysisResult.task_id.in_(select(Task.id).where(Task.payload["pcap_id"].as_integer() == pcap_id)))).all()
    for row in external:
        for engine in (row.content or {}).get("engines", []):
            name = engine.get("name", "")
            events = engine.get("events", {})
            if name == "zeek":
                for key in ("dns", "http", "ssl", "files"):
                    for item in events.get(key, []):
                        target = "dns" if key == "dns" else "http" if key == "http" else "tls" if key == "ssl" else "files"
                        result[target].append({**item, "source": "zeek"})
            elif name == "suricata":
                for item in events:
                    event_type = item.get("event_type", "")
                    if event_type in {"dns", "http"}:
                        result[event_type].append({**item, "source": "suricata"})
                    elif event_type == "fileinfo":
                        result["files"].append({**item, "source": "suricata"})
                    elif event_type == "alert":
                        result["alerts"].append({**item, "source": "suricata"})
    integration_rows = db.scalars(select(AnalysisResult).where(AnalysisResult.module == "integrations", AnalysisResult.task_id.in_(select(Task.id).where(Task.payload["pcap_id"].as_integer() == pcap_id)))).all()
    for row in integration_rows:
        for name, events in (row.content or {}).items():
            if not isinstance(events, list):
                continue
            for item in events:
                event_type = str(item.get("event_type") or item.get("_path") or "").lower()
                if name == "zeek":
                    if event_type == "dns":
                        result["dns"].append({**item, "source": "zeek"})
                    elif event_type == "http":
                        result["http"].append({**item, "source": "zeek"})
                    elif event_type in {"ssl", "tls"}:
                        result["tls"].append({**item, "source": "zeek"})
                    elif event_type == "files":
                        result["files"].append({**item, "source": "zeek"})
                elif name == "suricata":
                    if event_type in {"dns", "http"}:
                        result[event_type].append({**item, "source": "suricata"})
                    elif event_type == "fileinfo":
                        result["files"].append({**item, "source": "suricata"})
                    elif event_type == "alert":
                        result["alerts"].append({**item, "source": "suricata"})
    return result


@router.get("/pcaps/{pcap_id}/dns")
def pcap_dns(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"items": _external_details(pcap_id, db)["dns"]}


@router.get("/pcaps/{pcap_id}/http")
def pcap_http(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"items": _external_details(pcap_id, db)["http"]}


@router.get("/pcaps/{pcap_id}/tls")
def pcap_tls(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"items": _external_details(pcap_id, db)["tls"]}


@router.get("/pcaps/{pcap_id}/files")
def pcap_files(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"items": _external_details(pcap_id, db)["files"]}


@router.get("/pcaps/{pcap_id}/alerts")
def pcap_alerts(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    anomalies = [_serialize_anomaly(item) for item in db.scalars(select(Anomaly).where(Anomaly.pcap_id == pcap_id)).all()]
    findings = [_serialize_detection(item) for item in db.scalars(select(DetectionFinding).where(DetectionFinding.target_type == "pcap", DetectionFinding.target_id == str(pcap_id)).order_by(DetectionFinding.risk_score.desc())).all()]
    alerts = db.scalars(select(Alert).where(Alert.finding_id.in_([item["id"] for item in findings])).order_by(Alert.risk_score.desc())).all() if findings else []
    external = _external_details(pcap_id, db)["alerts"]
    merged: dict[str, Any] = {}
    for item in alerts:
        key = f"alert:{item.fingerprint}"
        merged.setdefault(key, {"kind": "alert", "severity": item.severity, "title": item.title, "description": item.summary, "evidence": serialize_alert(item), "source": item.source, "id": item.id})
    for item in anomalies:
        key = f"anomaly:{item['rule']}:{item['severity']}:{item['description']}"
        merged.setdefault(key, {"kind": "anomaly", "severity": item["severity"], "title": item["rule"], "description": item["description"], "evidence": item["evidence"], "source": "builtin"})
    for item in findings:
        key = f"finding:{item['engine']}:{item['rule_id']}:{item['timestamp']}"
        merged.setdefault(key, {"kind": "finding", "severity": item["severity"], "title": item["rule_id"], "description": item["recommendation"], "evidence": item["evidence"], "source": item["engine"], "id": item["id"]})
    for item in external:
        alert = item.get("alert", {}) or {}
        key = f"external:{item.get('source')}:{alert.get('signature_id', item.get('signature_id', ''))}:{item.get('timestamp', '')}"
        merged.setdefault(key, {"kind": "external", "severity": item.get("severity", "Medium"), "title": alert.get("signature", item.get("signature", "")), "description": alert.get("signature", ""), "evidence": item, "source": item.get("source", "external")})
    items = list(merged.values())
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return {"items": sorted(items, key=lambda item: severity_order.get(item.get("severity", "Low"), 9))}


@router.get("/tasks")
def list_tasks(status: str | None = None, kind: str | None = None, search: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(Task)
    if status:
        query = query.where(Task.status == status)
    if kind:
        query = query.where(Task.kind == kind)
    if search:
        query = query.where(or_(Task.kind.ilike(f"%{search}%"), Task.current_stage.ilike(f"%{search}%"), Task.error.ilike(f"%{search}%")))
    result = paginate(db, query.order_by(Task.id.desc()), page, page_size)
    return page_response([_serialize_task(item) for item in result["items"]], page, page_size, result["total"])


@router.post("/tasks")
def create_generic_task(payload: TaskCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, payload.kind, payload.payload)
    return _serialize_task(task)


@router.get("/tasks/{task_id}")
def task_detail(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "task not found")
    return _serialize_task(task)


@router.post("/audit/logs")
def analyze_log(payload: LogAnalysisRequest) -> dict[str, Any]:
    lines = payload.content.splitlines()
    context = DetectionContext(target_type="log", data={}, log_lines=lines)
    pipeline = DetectionPipeline(registry, RiskEngine())
    result = pipeline.run(context)
    return {"log_summary": log_analysis(lines), "findings": [item.to_dict() for item in result.findings], "risk": {"score": result.risk_score, "level": result.risk_level}}


@router.get("/audit/summary")
def audit(db: Session = Depends(get_db)) -> dict[str, Any]:
    assets = [_serialize_asset(item) for item in db.scalars(select(Asset)).all()]
    files = [_serialize_file(item) for item in db.scalars(select(FileRecord)).all()]
    pcaps = [_serialize_pcap(item) for item in db.scalars(select(PcapRecord)).all()]
    anomalies = [_serialize_anomaly(item) for item in db.scalars(select(Anomaly)).all()]
    return audit_summary(assets, files, pcaps, anomalies)


@router.post("/reports/generate")
def generate_report(payload: GenerateReportRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    assets = [_serialize_asset(item) for item in db.scalars(select(Asset)).all()]
    files = [_serialize_file(item) for item in db.scalars(select(FileRecord)).all()]
    pcaps = [_serialize_pcap(item) for item in db.scalars(select(PcapRecord)).all()]
    anomalies = [_serialize_anomaly(item) for item in db.scalars(select(Anomaly)).all()]
    findings = [_serialize_detection(item) for item in db.scalars(select(DetectionFinding).order_by(DetectionFinding.risk_score.desc())).all()]
    data_assets = [_serialize_data_asset(item) for item in db.scalars(select(DataAsset).order_by(DataAsset.id.desc())).all()]
    incidents = [_serialize_incident(item) for item in db.scalars(select(Incident).order_by(Incident.risk_score.desc())).all()]
    summary = build_summary(assets, files, pcaps, anomalies, audit_summary(assets, files, pcaps, anomalies), findings, data_assets, incidents)
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
    record = Report(title=payload.title, report_type=payload.report_type, format=report_format, storage_path=str(output), summary=summary)
    db.add(record)
    db.commit()
    db.refresh(record)
    return _serialize_report(record)


@router.get("/reports")
def list_reports(report_type: str | None = None, format: str | None = None, search: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(Report)
    if report_type:
        query = query.where(Report.report_type == report_type)
    if format:
        query = query.where(Report.format == format)
    if search:
        query = query.where(Report.title.ilike(f"%{search}%"))
    result = paginate(db, query.order_by(Report.id.desc()), page, page_size)
    return page_response([_serialize_report(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)) -> FileResponse:
    item = db.get(Report, report_id)
    if not item:
        raise HTTPException(404, "report not found")
    path = Path(item.storage_path)
    if not path.exists():
        raise HTTPException(404, "report file not found")
    return FileResponse(str(path), filename=path.name)


@router.get("/analysis/results")
def analysis_results(module: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    query = select(AnalysisResult)
    if module:
        query = query.where(AnalysisResult.module == module)
    return [
        {"id": item.id, "task_id": item.task_id, "module": item.module, "content": item.content, "score": item.score, "risk_level": item.risk_level, "created_at": item.created_at}
        for item in db.scalars(query.order_by(AnalysisResult.id.desc())).all()
    ]


@router.get("/incidents")
def list_incidents(severity: str | None = None, status: str | None = None, search: str | None = None, start_time: str | None = None, end_time: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(Incident)
    if severity:
        query = query.where(Incident.severity == severity)
    if status:
        query = query.where(Incident.status == status)
    if search:
        query = query.where(or_(Incident.title.ilike(f"%{search}%"), Incident.evidence["asset"].as_string().ilike(f"%{search}%"), Incident.evidence["ioc"].as_string().ilike(f"%{search}%")))
    query = _string_time_filter(query, Incident.timestamp, start_time, end_time)
    result = paginate(db, query.order_by(Incident.risk_score.desc(), Incident.timestamp.desc()), page, page_size)
    return page_response([_serialize_incident(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(Incident, incident_id)
    if not item:
        raise HTTPException(404, "incident not found")
    return _serialize_incident(item)


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(Incident, incident_id)
    if not item:
        raise HTTPException(404, "incident not found")
    for key in ("status", "severity", "title"):
        if key in payload:
            setattr(item, key, payload[key])
    db.commit()
    db.refresh(item)
    return _serialize_incident(item)


@router.post("/incidents/correlate")
def correlate_incidents(payload: dict[str, Any]) -> list[dict[str, Any]]:
    from app.engine.core.result import DetectionResult

    findings = [DetectionResult(**item) for item in payload.get("findings", [])]
    return [item.to_dict() for item in incident_engine.correlate(findings, int(payload.get("window_seconds", 3600)))]


@router.get("/iocs")
def list_iocs(ioc_type: str | None = None, source: str | None = None, search: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(IOC)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if source:
        query = query.where(IOC.source == source)
    if search:
        query = query.where(IOC.value.ilike(f"%{search}%"))
    result = paginate(db, query.order_by(IOC.id.desc()), page, page_size)
    return page_response([_serialize_ioc(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/iocs/{ioc_id}/associations")
def ioc_associations(ioc_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(IOC, ioc_id)
    if not item:
        raise HTTPException(404, "ioc not found")
    findings = db.scalars(select(DetectionFinding).where(DetectionFinding.evidence["value"].as_string() == item.value).order_by(DetectionFinding.risk_score.desc())).all()
    incidents = db.scalars(select(Incident).where(Incident.evidence["ioc"].as_string() == item.value).order_by(Incident.risk_score.desc())).all()
    assets = db.scalars(select(Asset).where(or_(Asset.ip == item.value, Asset.hostname == item.value))).all()
    return {
        "ioc": _serialize_ioc(item),
        "findings": [_serialize_detection(item) for item in findings],
        "incidents": [_serialize_incident(item) for item in incidents],
        "assets": [_serialize_asset(item) for item in assets],
    }


@router.get("/engine/registry")
def engine_registry() -> list[dict[str, Any]]:
    return [engine.metadata() for engine in registry.all()]


@router.get("/integrations")
def list_integrations() -> list[dict[str, Any]]:
    return integration_registry.metadata()


@router.post("/integrations/{name}/analyze")
def run_integration(name: str, payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        adapter = integration_registry.get(name)
    except KeyError as exc:
        raise HTTPException(404, "integration not found") from exc
    context = DetectionContext(target_type="integration", target_id=name, data=payload.get("context", {}))
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
        row = _upsert_incident(db, incident, None)
        alert, created = create_incident_alert(db, row)
        if alert:
            alerts.append((alert, created))
    db.commit()
    for alert, created in alerts:
        publish_alert(alert.id, event_type="alert.created" if created else "alert.updated")
    return result.to_dict()


@router.post("/integrations/offline/upload")
async def upload_offline(file: UploadFile = File(...), resource_type: str | None = Form(None), name: str | None = Form(None), version: str | None = Form(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    data = await file.read()
    return import_uploaded_offline(db, file.filename or "offline.bundle", data, resource_type, name, version).to_dict()


@router.post("/integrations/offline/import")
def import_offline(payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
    path = payload.get("path", "")
    if not path:
        raise HTTPException(400, "path is required")
    candidate = safe_path(settings.integration_dir, path)
    return import_offline_path(db, candidate, payload.get("resource_type"), payload.get("name"), payload.get("version")).to_dict()


@router.get("/offline/resources")
def offline_resources(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return list_offline_resources(db)


@router.get("/offline/cves")
def offline_cves(search: str | None = None, limit: int = Query(100, le=1000), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return list_local_cves(db, search or "", limit)


@router.post("/offline/upload")
async def upload_offline_alt(file: UploadFile = File(...), resource_type: str | None = Form(None), name: str | None = Form(None), version: str | None = Form(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    data = await file.read()
    return import_uploaded_offline(db, file.filename or "offline.bundle", data, resource_type, name, version).to_dict()


@router.post("/engine/pipeline")
def run_engine_pipeline(payload: dict[str, Any]) -> dict[str, Any]:
    context = DetectionContext(
        target_type=payload.get("target_type", "manual"),
        target_id=payload.get("target_id"),
        data=payload.get("data", {}),
        assets=payload.get("assets", []),
        flows=payload.get("flows", []),
        packets=payload.get("packets", []),
        metadata=payload.get("metadata", {}),
        log_lines=payload.get("log_lines", []),
    )
    pipeline = DetectionPipeline(registry, RiskEngine())
    return pipeline.run(context).to_dict()


@router.get("/detections")
def list_detections(severity: str | None = None, engine: str | None = None, risk_level: str | None = None, target_type: str | None = None, target_id: str | None = None, search: str | None = None, start_time: str | None = None, end_time: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
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
        query = query.where(or_(DetectionFinding.rule_id.ilike(f"%{search}%"), DetectionFinding.engine.ilike(f"%{search}%"), DetectionFinding.recommendation.ilike(f"%{search}%")))
    query = _string_time_filter(query, DetectionFinding.timestamp, start_time, end_time)
    result = paginate(db, query.order_by(DetectionFinding.risk_score.desc()), page, page_size)
    return page_response([_serialize_detection(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/detections/{detection_id}")
def detection_detail(detection_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(DetectionFinding, detection_id)
    if not item:
        raise HTTPException(404, "detection not found")
    incidents = db.scalars(select(Incident).where(Incident.findings["items"].as_string().ilike(f"%{item.rule_id}%"))).all()
    pcap = db.get(PcapRecord, int(item.target_id)) if item.target_type == "pcap" and str(item.target_id).isdigit() else None
    alert = db.scalar(select(Alert).where(Alert.finding_id == item.id))
    return {"detection": _serialize_detection(item), "related_incidents": [_serialize_incident(item) for item in incidents], "pcap": _serialize_pcap(pcap) if pcap else None, "alert": serialize_alert(alert) if alert else None}


@router.get("/alerts")
def list_alerts(status: str | None = None, severity: str | None = None, source: str | None = None, probe_id: int | None = None, start: str | None = None, end: str | None = None, search: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
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
        query = query.where(or_(Alert.title.ilike(f"%{search}%"), Alert.summary.ilike(f"%{search}%")))
    result = paginate(db, query.order_by(Alert.risk_score.desc(), Alert.last_seen.desc()), page, page_size)
    return page_response([serialize_alert(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/alerts/summary")
def alert_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    status_rows = db.execute(select(Alert.status, func.count(Alert.id)).group_by(Alert.status)).all()
    severity_rows = db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all()
    unhandled = db.scalar(select(func.count(Alert.id)).where(Alert.status == "new", Alert.severity.in_(["Critical", "High"]))) or 0
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

    return StreamingResponse(event_source(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


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
        pcap = db.get(PcapRecord, int(finding.target_id)) if str(finding.target_id).isdigit() else None
    deliveries = db.scalars(select(AlertDelivery).where(AlertDelivery.alert_id == alert.id).order_by(AlertDelivery.id.desc())).all()
    return {
        "alert": serialize_alert(alert),
        "finding": _serialize_detection(finding) if finding else None,
        "incident": _serialize_incident(incident) if incident else None,
        "probe": _serialize_probe(probe) if probe else None,
        "pcap": _serialize_pcap(pcap) if pcap else None,
        "deliveries": [
            {"id": item.id, "channel": item.channel, "target": item.target, "status": item.status, "attempts": item.attempts, "last_error": item.last_error, "sent_at": item.sent_at}
            for item in deliveries
        ],
    }


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
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


@router.get("/risk/summary")
def risk_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(DetectionFinding.risk_level, func.count(DetectionFinding.id)).group_by(DetectionFinding.risk_level)).all()
    engine_rows = db.execute(select(DetectionFinding.engine, func.count(DetectionFinding.id)).group_by(DetectionFinding.engine)).all()
    asset_rows = db.execute(select(Asset.risk_level, func.count(Asset.id)).group_by(Asset.risk_level)).all()
    data_rows = db.execute(select(DataAsset.sensitivity, func.count(DataAsset.id)).group_by(DataAsset.sensitivity)).all()
    return {
        "count": db.scalar(select(func.count(DetectionFinding.id))) or 0,
        "risk_levels": {level: count for level, count in rows},
        "engines": {engine: count for engine, count in engine_rows},
        "asset_risk": {risk: count for risk, count in asset_rows},
        "data_sensitivity": {sensitivity: count for sensitivity, count in data_rows},
        "max_score": db.scalar(select(func.max(DetectionFinding.risk_score))) or 0,
        "avg_score": db.scalar(select(func.avg(DetectionFinding.risk_score))) or 0,
    }


@router.get("/data/assets")
def data_assets(search: str | None = None, sensitivity: str | None = None, asset_type: str | None = None, source: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(DataAsset)
    if search:
        query = query.where(DataAsset.name.ilike(f"%{search}%"))
    if sensitivity:
        query = query.where(DataAsset.sensitivity == sensitivity)
    if asset_type:
        query = query.where(DataAsset.asset_type == asset_type)
    if source:
        query = query.where(DataAsset.source == source)
    result = paginate(db, query.order_by(DataAsset.id.desc()), page, page_size)
    return page_response([_serialize_data_asset(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/data/assets/{data_asset_id}")
def data_asset_detail(data_asset_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(DataAsset, data_asset_id)
    if not item:
        raise HTTPException(404, "data asset not found")
    findings = db.scalars(select(DetectionFinding).where(DetectionFinding.evidence["file"].as_string() == item.source).order_by(DetectionFinding.risk_score.desc())).all()
    pii_summary: dict[str, int] = Counter()
    for column in item.columns:
        for category in column.get("categories", []):
            pii_summary[category] += 1
    return {"data_asset": _serialize_data_asset(item), "findings": [_serialize_detection(item) for item in findings], "pii_summary": dict(pii_summary)}


@router.get("/graph")
def graph(db: Session = Depends(get_db)) -> dict[str, Any]:
    relations = [
        {"source_node": item.source_node, "source_type": item.source_type, "target_node": item.target_node, "target_type": item.target_type, "relation": item.relation, "risk": item.risk}
        for item in db.scalars(select(GraphRelation).order_by(GraphRelation.id.desc())).all()
    ]
    assets = db.scalars(select(Asset)).all()
    data_assets = db.scalars(select(DataAsset)).all()
    incidents = db.scalars(select(Incident)).all()
    iocs = db.scalars(select(IOC)).all()
    probes = db.scalars(select(Probe)).all()
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_node(node_id: str, label: str, node_type: str, risk: str = "Low", metadata: dict[str, Any] | None = None) -> None:
        if node_id in seen:
            return
        seen.add(node_id)
        nodes.append({"id": node_id, "name": label, "type": node_type, "risk": risk, "metadata": metadata or {}})

    for item in probes:
        add_node(f"probe:{item.id}", item.name, "probe", item.status, {"ip": item.ip_address})
    for item in assets:
        add_node(f"asset:{item.id}", item.ip or item.hostname, "host", item.risk_level, {"hostname": item.hostname, "service": item.service, "port": item.port})
    for item in data_assets:
        add_node(f"data:{item.id}", item.name, "data_asset", item.sensitivity, {"asset_type": item.asset_type})
    for item in iocs:
        add_node(f"ioc:{item.id}", item.value, "ioc", "High", {"ioc_type": item.ioc_type})
    for item in incidents:
        add_node(f"incident:{item.id}", item.title, "incident", item.risk_level, {"status": item.status})
    return {"nodes": nodes, "relations": relations}


@router.get("/dashboard/summary")
def dashboard(db: Session = Depends(get_db)) -> dict[str, Any]:
    healthy_integrations = sum(1 for item in integration_registry.metadata() if item.get("healthy"))
    return {
        "assets": db.scalar(select(func.count(Asset.id))) or 0,
        "files": db.scalar(select(func.count(FileRecord.id))) or 0,
        "pcaps": db.scalar(select(func.count(PcapRecord.id))) or 0,
        "anomalies": db.scalar(select(func.count(Anomaly.id))) or 0,
        "tasks": db.scalar(select(func.count(Task.id))) or 0,
        "reports": db.scalar(select(func.count(Report.id))) or 0,
        "probes": db.scalar(select(func.count(Probe.id))) or 0,
        "incidents": db.scalar(select(func.count(Incident.id))) or 0,
        "iocs": db.scalar(select(func.count(IOC.id))) or 0,
        "alerts": db.scalar(select(func.count(Alert.id))) or 0,
        "open_alerts": db.scalar(select(func.count(Alert.id)).where(Alert.status == "new")) or 0,
        "high_risk_findings": db.scalar(select(func.count(DetectionFinding.id)).where(DetectionFinding.risk_level.in_(["Critical", "High"]))) or 0,
        "open_incidents": db.scalar(select(func.count(Incident.id)).where(Incident.status == "open")) or 0,
        "high_risk_assets": db.scalar(select(func.count(Asset.id)).where(Asset.risk_level.in_(["Critical", "High"]))) or 0,
        "sensitive_data_assets": db.scalar(select(func.count(DataAsset.id)).where(DataAsset.sensitivity.in_(["Critical", "High"]))) or 0,
        "online_probes": db.scalar(select(func.count(Probe.id)).where(Probe.status == "online")) or 0,
        "healthy_integrations": healthy_integrations,
    }


@router.get("/dashboard/risk-trend")
def risk_trend(range: str = Query("7d"), db: Session = Depends(get_db)) -> dict[str, Any]:
    days = 1 if range == "24h" else 7
    since = datetime.now(UTC) - timedelta(days=days)
    rows = db.scalars(select(DetectionFinding).where(DetectionFinding.created_at >= since).order_by(DetectionFinding.created_at)).all()
    buckets: dict[str, dict[str, float | int]] = {}
    for item in rows:
        key = item.created_at.strftime("%Y-%m-%d") if days > 1 else item.created_at.strftime("%Y-%m-%d %H:00")
        entry = buckets.setdefault(key, {"risk_score": 0, "count": 0, "critical": 0, "high": 0})
        entry["risk_score"] = max(float(entry["risk_score"]), item.risk_score)
        entry["count"] = int(entry["count"]) + 1
        if item.risk_level == "Critical":
            entry["critical"] = int(entry["critical"]) + 1
        elif item.risk_level == "High":
            entry["high"] = int(entry["high"]) + 1
    return {"range": range, "items": [{"time": key, **value} for key, value in sorted(buckets.items())]}


@router.get("/dashboard/severity")
def dashboard_severity(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(DetectionFinding.severity, func.count(DetectionFinding.id)).group_by(DetectionFinding.severity)).all()
    return {"items": [{"severity": severity, "count": count} for severity, count in rows]}


@router.get("/dashboard/engines")
def dashboard_engines(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(DetectionFinding.engine, func.count(DetectionFinding.id)).group_by(DetectionFinding.engine)).all()
    return {"items": [{"engine": engine, "count": count} for engine, count in rows]}


@router.get("/dashboard/incidents")
def dashboard_incidents(limit: int = Query(10, le=100), db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.scalars(select(Incident).order_by(Incident.risk_score.desc()).limit(limit)).all()
    return {"items": [_serialize_incident(item) for item in rows]}


@router.get("/dashboard/high-risk-assets")
def dashboard_high_risk_assets(limit: int = Query(10, le=100), db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.scalars(select(Asset).order_by(Asset.risk_level.desc(), Asset.id.desc()).limit(limit)).all()
    return {"items": [_serialize_asset(item) for item in rows]}


@router.get("/dashboard/sensitive-data")
def dashboard_sensitive_data(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(DataAsset.sensitivity, func.count(DataAsset.id)).group_by(DataAsset.sensitivity)).all()
    return {"items": [{"category": category, "count": count} for category, count in rows]}
