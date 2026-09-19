from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
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
from app.api.integrations import (
    router as integrations_router,
)
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
from app.api.rules import (
    router as rules_router,
)
from app.api.runtime_status import engine_rule_counts, merge_capability, read_worker_capabilities
from app.api.task_presenter import serialize_task
from app.api.tasks import (
    router as tasks_router,
)
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
from app.models import (
    AdminSession,
    Asset,
    Probe,
    Task,
    User,
)
from app.schemas import (
    LoginRequest,
    ScanRequest,
)
from app.services.task_dispatch import (
    NETWORK_SCAN,
    queue_depth,
)
from app.services.task_service import create_task
from app.services.test_service import clear_test_data, import_test_data, test_status

router = APIRouter(prefix="/api/v1")


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
    capabilities = read_worker_capabilities()
    # A worker is online only if its Redis capability heartbeat is fresh.
    analysis_worker = "online" if capabilities else "offline"
    if capabilities and any(item["tshark"].get("available") for item in capabilities if isinstance(item.get("tshark"), dict)):
        analysis_worker = "ready"
    merged = merge_capability(capabilities)
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
        "engine_rule_counts": engine_rule_counts(),
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
router.include_router(integrations_router)
router.include_router(rules_router)
