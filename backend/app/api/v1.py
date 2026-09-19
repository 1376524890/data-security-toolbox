from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from sqlalchemy import false, func, select
from sqlalchemy.orm import Session

from app.api.alerts import (
    router as alerts_router,
)
from app.api.assets import (
    router as assets_router,
)
from app.api.assets import (
    serialize_asset,
)
from app.api.dashboard import (
    router as dashboard_router,
)
from app.api.data_assets import SENSITIVE_RULE_BUCKETS as SENSITIVE_RULE_BUCKETS
from app.api.data_assets import _sensitive_bucket as _sensitive_bucket
from app.api.data_assets import _serialize_data_asset as _serialize_data_asset
from app.api.data_assets import data_asset_detail as data_asset_detail
from app.api.data_assets import data_assets as data_assets
from app.api.data_assets import router as data_assets_router
from app.api.data_assets import sensitive_findings as sensitive_findings
from app.api.dependencies import dispatch_task
from app.api.detections import (
    router as detections_router,
)
from app.api.engines import (
    router as engines_router,
)
from app.api.files import (
    router as files_router,
)
from app.api.finding_presenter import ATTACK_MAP as ATTACK_MAP
from app.api.finding_presenter import _attack as _attack
from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.incidents import (
    router as incidents_router,
)
from app.api.pagination import page_response
from app.api.pcaps import (
    router as pcaps_router,
)
from app.api.probe_presenter import serialize_probe
from app.api.probes import (
    router as probes_router,
)
from app.api.reports import (
    router as reports_router,
)
from app.api.rule_presenter import rule_file_entries
from app.api.task_presenter import serialize_task
from app.api.tasks import (
    router as tasks_router,
)
from app.application.analysis import upsert_incident
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    clear_admin_cookie,
    create_admin_session,
    ensure_admin,
    hash_token,
    set_admin_cookie,
    verify_password,
)
from app.core.storage import safe_path
from app.engine.core.context import DetectionContext
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
    AdminSession,
    Alert,
    Asset,
    DetectionFinding,
    LocalCve,
    Probe,
    Task,
    User,
)
from app.schemas import (
    LoginRequest,
    ScanRequest,
)
from app.services.alert_service import (
    create_finding_alert,
    create_incident_alert,
    publish_alert,
)
from app.services.task_dispatch import (
    NETWORK_SCAN,
    queue_depth,
)
from app.services.task_service import create_task
from app.services.test_service import clear_test_data, import_test_data, test_status

router = APIRouter(prefix="/api/v1")
incident_engine = IncidentEngine()


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


def _require_test_data_import() -> None:
    """The manual test pack is an operator opt-in, never a delivery feature."""
    if not settings.test_data_import_enabled:
        raise HTTPException(403, "test data import is disabled")


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


def _engine_rule_counts() -> dict[str, int]:
    base = Path(__file__).resolve().parents[1] / "rules"
    counts: dict[str, int] = {}
    for sub, engine in (("network", "traffic_engine"), ("data", "data_engine"), ("logs", "sigma_log_engine"), ("compliance", "compliance_engine")):
        directory = base / sub
        count = 0
        if directory.exists():
            for path in directory.rglob("*"):
                if path.is_file() and path.suffix in {".yaml", ".yml", ".yar"}:
                    count += 1
        counts[engine] = count
    counts["yara"] = sum(1 for _ in (base / "data").glob("*.yar")) if (base / "data").exists() else 0
    return counts


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, Any]:
    redis_ok = False
    try:
        import redis as redis_lib
        redis_ok = bool(redis_lib.Redis.from_url(settings.redis_url, socket_connect_timeout=1, socket_timeout=1).ping())
    except Exception:
        redis_ok = False
    try:
        running, queued, workers = queue_depth()
    except Exception:
        running = 0
        queued = 0
        workers = 0
    oldest = db.scalar(select(func.min(Task.created_at)).where(Task.status.in_(["Pending", "Running"])))
    if oldest and oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=UTC)
    oldest_age = max(0.0, (datetime.now(UTC) - oldest).total_seconds()) if oldest else 0.0
    storage_bytes = sum(path.stat().st_size for path in settings.storage_dir.rglob("*") if path.is_file())
    probes = db.scalars(select(Probe)).all()
    probe_statuses = {item: 0 for item in ("online", "degraded", "offline", "auth_error")}
    for probe in probes:
        probe_statuses[serialize_probe(probe)["status"]] = probe_statuses.get(serialize_probe(probe)["status"], 0) + 1
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
        "engine_rule_counts": _engine_rule_counts(),
        "storage_usage_bytes": storage_bytes,
        "storage_max_bytes": settings.pcap_storage_max_gb * 1024 * 1024 * 1024,
        "queue": {"pending": db.scalar(select(func.count(Task.id)).where(Task.status == "Pending")) or 0, "running": running, "oldest_pending_age": oldest_age},
        "probe": {"count": len(probes), **probe_statuses},
        # Capabilities the console must honour rather than probe for itself.
        "features": {"test_data_import": settings.test_data_import_enabled},
    }


@router.post("/scan")
def start_scan(payload: ScanRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Trigger an active network scan.

    Without ``probe_id`` the platform itself discovers hosts and enumerates
    services (nmap ``-Pn -sT`` with a built-in TCP-connect fallback). With
    ``probe_id`` the bounded scan is queued for that probe, which is the only
    way to reach a segment the platform container cannot route to.
    """
    if payload.probe_id:
        from app.services.probe_task_service import queue_probe_scan

        if not db.get(Probe, payload.probe_id):
            raise HTTPException(404, "probe not found")
        from app.services.scan_service import select_ports
        ports = payload.ports or select_ports(min(payload.top_ports, 256))
        task = queue_probe_scan(db, payload.probe_id, {
            "targets": [payload.target],
            "ports": ports,
            "max_hosts": 256,
            "concurrency": 32,
            "connect_timeout": 0.5,
            "timeout_seconds": 300,
        })
        return {**serialize_task(task), "location": "probe", "probe_id": payload.probe_id}
    task = create_task(db, "scan", {"target": payload.target, "discovery": payload.discovery, "top_ports": payload.top_ports, "ports": payload.ports, "public_exposed": payload.public_exposed, "nuclei": payload.nuclei, "nuclei_tags": payload.nuclei_tags, "nuclei_templates": payload.nuclei_templates})
    dispatch_task(task.id, NETWORK_SCAN)
    return {**serialize_task(task), "location": "platform"}


@router.get("/scan/{task_id}")
def scan_result(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return a scan task's progress / result (assets + findings)."""
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "scan task not found")
    result = serialize_task(task)
    hosts = list((task.result or {}).get("hosts") or [])
    if task.kind == "probe_scan":
        probe_id = (task.payload or {}).get("probe_id")
        query = select(Asset).where(Asset.probe_id == probe_id, Asset.extra["source"].as_string() == "probe_scan")
    else:
        query = select(Asset).where(Asset.extra["source"].as_string().in_(["platform_scan", "nmap_scan"]))
    if hosts:
        query = query.where(Asset.ip.in_(hosts))
    else:
        query = query.where(false())
    result["scanned_assets"] = [serialize_asset(item) for item in db.scalars(query.order_by(Asset.ip, Asset.port)).all()]
    return result


@router.post("/test/import")
def import_test(payload: dict[str, Any] | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Import the manual test pack (labeled test data) for demos/verification."""
    _require_test_data_import()
    return import_test_data(db)


@router.post("/test/clear")
def clear_test(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Remove all imported test data (test-demo probe + linked records)."""
    _require_test_data_import()
    return clear_test_data(db)


@router.get("/test/status")
def get_test_status(db: Session = Depends(get_db)) -> dict[str, Any]:
    return test_status(db)


@router.get("/integrations")
def list_integrations() -> list[dict[str, Any]]:
    entries = list(integration_registry.metadata())
    # The API container may lack the Zeek/Suricata binaries while a live
    # analysis worker reports the capability (published to Redis). Surface the
    # worker's availability so the UI doesn't show a working engine as
    # "unavailable" just because the API container can't run it.
    worker_caps = _merge_capability(_read_worker_capabilities())
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
    sigma_count = _engine_rule_counts().get("sigma_log_engine", 0)
    entries.append({
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
    })
    return entries


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
        row = upsert_incident(db, incident, None)
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
def offline_cves(search: str | None = None, limit: int = Query(100, ge=1, le=1000),
                 page: int | None = Query(None, ge=1), page_size: int = Query(50, ge=1, le=200),
                 db: Session = Depends(get_db)) -> Any:
    # Keep the legacy array contract for existing integrations.
    if page is None:
        return list_local_cves(db, search or "", limit)
    query = select(func.count()).select_from(LocalCve)
    if search:
        query = query.where(LocalCve.cve_id.ilike(f"%{search}%"))
    total = db.scalar(query) or 0
    return page_response(list_local_cves(db, search or "", page_size, (page - 1) * page_size), page, page_size, total)


@router.post("/offline/upload")
async def upload_offline_alt(file: UploadFile = File(...), resource_type: str | None = Form(None), name: str | None = Form(None), version: str | None = Form(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    data = await file.read()
    return import_uploaded_offline(db, file.filename or "offline.bundle", data, resource_type, name, version).to_dict()


@router.get("/rules")
def list_rules(rule_type: str | None = Query(None), engine: str | None = Query(None), include_content: bool = Query(True), db: Session = Depends(get_db)) -> dict[str, Any]:
    """List Sigma / Suricata / YARA rules with content."""
    items = rule_file_entries(db, engine=engine or '', include_content=include_content)
    if rule_type:
        items = [item for item in items if item["type"] == rule_type]
    if engine:
        items = [item for item in items if item["engine"] == engine]
    return {"items": items, "total": len(items)}


@router.get('/rules/content')
def rule_content(path: str, engine: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = next((item for item in rule_file_entries(db, engine, include_content=False)
                 if item['path'] == path), None)
    if item is None:
        raise HTTPException(404, '规则不存在')
    if item['type'] == 'builtin':
        from app.rules.code_catalog import definition
        item['content'] = definition(engine, item['rule_id'])['content']
    else:
        item['content'] = Path(path).read_text(encoding='utf-8', errors='replace')
    return item


# Legacy asset projection and sensitive findings share a dedicated read boundary.

router.include_router(data_assets_router)
router.include_router(pcaps_router)
router.include_router(files_router)
router.include_router(assets_router)
router.include_router(incidents_router)
router.include_router(alerts_router)
router.include_router(tasks_router)
router.include_router(reports_router)
router.include_router(detections_router)
router.include_router(engines_router)
router.include_router(dashboard_router)
router.include_router(probes_router)
