from __future__ import annotations

import json
import secrets
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
from fastapi.responses import FileResponse
from sqlalchemy import false, func, or_, select
from sqlalchemy.orm import Session

from app.services.probe_task_service import PROBE_TASK_KINDS, TERMINAL, expire_probe_tasks, visible_tasks
from app.api.data_assets import router as data_assets_router
from app.api.data_assets import _serialize_data_asset as _serialize_data_asset
from app.api.data_assets import data_assets as data_assets
from app.api.data_assets import data_asset_detail as data_asset_detail
from app.api.data_assets import SENSITIVE_RULE_BUCKETS as SENSITIVE_RULE_BUCKETS
from app.api.data_assets import _sensitive_bucket as _sensitive_bucket
from app.api.data_assets import sensitive_findings as sensitive_findings
from app.api.finding_presenter import ATTACK_MAP as ATTACK_MAP
from app.api.finding_presenter import _attack as _attack
from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.services.probe_service import ProbeInUseError, ProbeNotFoundError, delete_probe_record
from app.api.pagination import page_response, paginate
from app.core.config import settings
from app.core.datetimes import aware as _aware
from app.core.database import get_db
from app.core.security import (
    clear_admin_cookie,
    create_admin_session,
    ensure_admin,
    hash_token,
    require_probe_headers,
    require_active_admin,
    set_admin_cookie,
    verify_password,
    verify_token,
)
from app.core.storage import safe_path
from app.deployment.enrollment import EnrollmentError, consume_enrollment
from app.deployment.record import DeploymentError
from app.deployment.removal import create_removal_deployment
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
    ProbeDeployment,
    LocalCve,
    Report,
    Task,
    User,
)
from app.schemas import (
    GenerateReportRequest,
    Heartbeat,
    LogAnalysisRequest,
    LoginRequest,
    ProbeDeleteRequest,
    ProbeRegister,
    ProbeScanRequest,
    ScanRequest,
    TaskCreate,
)
from app.services.alert_service import (
    create_finding_alert,
    create_incident_alert,
    publish_alert,
    serialize_alert,
)
from app.rules.catalog import CATALOG
from app.services.audit_service import audit_summary, log_analysis
from app.services.crypto_profile import build_crypto_profile
from app.services.protocol_service import protocol_layer
from app.services.test_service import clear_test_data, import_test_data, test_status
from app.services.report_service import build_summary, render_html, render_pdf
from app.application.analysis import upsert_incident
from app.services.task_dispatch import (
    ANALYZE_ASSETS,
    NETWORK_SCAN,
    dispatch_probe_deployment,
    dispatch_task_row,
    queue_depth,
)
from app.services.task_service import create_task
from app.api.pcaps import (
    router as pcaps_router,
    serialize_anomaly,
    serialize_flow,
    serialize_pcap,
)
from app.api.task_presenter import serialize_task
from app.api.files import (
    router as files_router,
    serialize_file,
)
from app.api.assets import (
    router as assets_router,
    serialize_asset,
)
from app.api.incident_presenter import serialize_incident
from app.api.incidents import (
    router as incidents_router,
)
from app.api.query_filters import string_time_filter as _string_time_filter
from app.api.alerts import (
    router as alerts_router,
)
from app.api.probe_presenter import serialize_probe
from app.api.rule_presenter import rule_file_entries

router = APIRouter(prefix="/api/v1")
incident_engine = IncidentEngine()


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


def _dispatch(task_id: int, task_name: str, *args: Any) -> None:
    """Queue one of the platform's analysis tasks by its registered name.

    The task row id always travels as the last argument, which is the calling
    convention every worker task keeps.
    """
    dispatch_task_row(task_name, task_id, *args)


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


def _merge_metadata(base: dict[str, Any] | None, incoming: dict[str, Any] | None) -> dict[str, Any]:
    """Deep-merge probe metadata so concurrent loops (heartbeat / asset / file)
    never clobber each other's keys. Lists and scalars are replaced."""
    merged: dict[str, Any] = dict(base or {})
    for key, value in (incoming or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_metadata(merged[key], value)
        else:
            merged[key] = value
    return merged


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


# Internal engine name -> (UI slug, display label). The console routes predate
# the engine names (``/engines/sigma`` vs ``sigma_log_engine``), so the mapping
# lives server-side: every view that lists engines or filters findings by
# engine reads it from ``/engine/registry`` instead of hard-coding a list.
ENGINE_PRESENTATION: dict[str, tuple[str, str]] = {
    "asset_engine": ("asset", "资产引擎"),
    "protocol_engine": ("protocol", "协议引擎"),
    "traffic_engine": ("traffic", "流量引擎"),
    "data_engine": ("data", "数据引擎"),
    "sigma_log_engine": ("sigma", "Sigma 日志引擎"),
    "compliance_engine": ("compliance", "合规引擎"),
    "dlp_engine": ("dlp", "数据防泄露引擎"),
    "threat_intel": ("ioc", "威胁情报引擎"),
}


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


@router.post("/probes/register")
def register_probe(payload: ProbeRegister, x_probe_bootstrap_token: str | None = Header(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    if payload.deployment_id:
        deployment = db.get(ProbeDeployment, payload.deployment_id)
        if not deployment:
            raise HTTPException(404, "deployment not found")
        probe = db.scalar(select(Probe).where(Probe.deployment_id == deployment.id))
        if not probe:
            name = deployment.name
            if db.scalar(select(Probe).where(Probe.name == name)):
                name = f"{name}-{deployment.id}"
            probe = Probe(
                name=name,
                hostname=payload.hostname,
                ip_address=payload.ip_address,
                extra=payload.metadata,
                status="offline",
                deployment_id=deployment.id,
            )
            db.add(probe)
            db.flush()
        try:
            consume_enrollment(db, deployment.id, x_probe_bootstrap_token or "", probe.id)
        except EnrollmentError as exc:
            raise HTTPException(401, str(exc))
        token = secrets.token_urlsafe(32)
        probe.token = ""
        probe.token_hash = hash_token(token)
        probe.status = "online"
        probe.last_seen = datetime.now(UTC)
        deployment.probe_id = probe.id
        deployment.registered_at = datetime.now(UTC)
        deployment.status = "REGISTERED"
        deployment.current_stage = "REGISTERED"
        db.commit()
        return {"id": probe.id, "name": probe.name, "token": token, "deployment_id": deployment.id}
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
        probe.extra = _merge_metadata(probe.extra or {}, payload.metadata or {})
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
    probe.extra = _merge_metadata(probe.extra or {}, metadata)
    probe.last_seen = datetime.now(UTC)
    if probe.deployment_id:
        deployment = db.get(ProbeDeployment, probe.deployment_id)
        if deployment and deployment.status in {"WAIT_CALLBACK", "REGISTERED"}:
            deployment.first_heartbeat_at = datetime.now(UTC)
            deployment.status = "ONLINE"
            deployment.current_stage = "ONLINE"
            deployment.progress = 100
    db.commit()
    # Tells the probe which rule version to expect on the next sync. Older probes
    # ignore the extra key, so the heartbeat stays backward compatible.
    return {"status": "ok", "latest_ruleset_version": _latest_ruleset_version(db)}


def _latest_ruleset_version(db: Session) -> str:
    """Active rule version, or "" when rule sets are not available yet."""
    try:
        from app.services.ruleset_service import active_version, get_or_create_rule_set

        row = active_version(db, get_or_create_rule_set(db))
        return row.version if row else ""
    except Exception:
        return ""


@router.get("/probes")
def list_probes(status: str | None = None, search: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(Probe)
    if status:
        query = query.where(Probe.status == status)
    if search:
        query = query.where(or_(Probe.name.ilike(f"%{search}%"), Probe.hostname.ilike(f"%{search}%"), Probe.ip_address.ilike(f"%{search}%")))
    result = paginate(db, query.order_by(Probe.id.desc()), page, page_size)
    return page_response([serialize_probe(item) for item in result["items"]], page, page_size, result["total"])


def _probe_removal_target(db: Session, probe: Probe, payload: ProbeDeleteRequest) -> tuple[str, int, str]:
    """Decide which host to connect to for a removal, and as whom.

    The probe's own deployment recorded how the platform reached that host, so
    that is the default and keeps the console one click away from a clean
    removal. The request may override it, which is what makes the same button
    work for a probe that was registered by hand, or whose deployment row is
    already gone.
    """
    deployment = db.get(ProbeDeployment, probe.deployment_id) if probe.deployment_id else None
    if deployment is None:
        deployment = db.scalar(
            select(ProbeDeployment)
            .where(ProbeDeployment.probe_id == probe.id)
            .order_by(ProbeDeployment.id.desc())
        )
    host = payload.host or (deployment.host if deployment else "") or probe.ip_address
    if not host:
        raise HTTPException(400, "无法确定探针主机地址，请在请求中提供 host")
    port = payload.port or (deployment.port if deployment else 0) or 22
    username = payload.username or (deployment.username if deployment else "") or "root"
    return host, int(port), username


@router.delete("/probes/{probe_id}", dependencies=[Depends(require_active_admin)])
def delete_probe(
    probe_id: int,
    payload: ProbeDeleteRequest | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_active_admin),
) -> dict[str, Any]:
    """Delete a probe record, optionally stripping its host in the same step.

    Without a body nothing on the target host changes: the record is dropped and
    everything the probe collected stays as it is. With ``remove_remote`` the
    request becomes a removal first - the platform connects to the probe's last
    known host, runs the uninstaller, and only then drops the record - so a
    removal that fails keeps the very record that says which host still has
    probe files on it.

    The steps run in that order on purpose. Deleting the record first would
    strand the host: nobody would know the address to clean, and the credential
    that could clean it lives on the deployment the record pointed at.
    """
    probe = db.get(Probe, probe_id)
    if not probe:
        raise HTTPException(404, "探针不存在")
    if payload is None or not payload.remove_remote:
        try:
            return delete_probe_record(db, probe_id)
        except ProbeNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ProbeInUseError as exc:
            raise HTTPException(409, exc.message) from exc
    host, port, username = _probe_removal_target(db, probe, payload)
    try:
        deployment = create_removal_deployment(
            db,
            host=host,
            port=port,
            username=username,
            auth_type=payload.auth_type,
            password=payload.password,
            private_key=payload.private_key,
            key_passphrase=payload.key_passphrase,
            name=f"remove-{probe.name}",
            idempotency_key=f"probe-{probe_id}-removal-{secrets.token_hex(8)}",
            created_by=user.username,
            probe_id=probe_id,
            options={
                "keep_data": payload.keep_data,
                "keep_user": payload.keep_user,
                "remove_user": payload.remove_user,
                "delete_record": True,
            },
        )
    except DeploymentError as exc:
        raise HTTPException(409, exc.message) from exc
    db.commit()
    dispatch_probe_deployment(deployment.id)
    return {"status": "queued", "action": "uninstall", "deployment_id": deployment.id}


@router.post("/probes/{probe_id}/analyze")
def analyze_probe_assets(probe_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, "assets", {"probe_id": probe_id})
    _dispatch(task.id, ANALYZE_ASSETS, probe_id)
    return serialize_task(task)


@router.get("/probes/{probe_id}/tasks")
def probe_tasks(probe_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    expire_probe_tasks(db)
    db.commit()
    tasks = db.scalars(select(Task).where(visible_tasks(), Task.payload["probe_id"].as_integer() == probe_id).order_by(Task.id.desc()).limit(50)).all()
    return [serialize_task(item) for item in tasks]


@router.get("/crypto/probe-profile")
def crypto_probe_profile(probe_id: int = Query(..., ge=1), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Build a probe-derived crypto / password profile for the GB/T 39786
    assessment tool, so the UI can auto-fill its inputs from what the probe
    actually observed (service banners, TLS handshake metadata)."""
    try:
        return build_crypto_profile(db, probe_id)
    except ValueError:
        raise HTTPException(404, "probe not found")


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
    _dispatch(task.id, NETWORK_SCAN)
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


@router.post("/probes/{probe_id}/scan")
def probe_scan(probe_id: int, payload: ProbeScanRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Probe-authenticated trigger for automated network environment scanning."""
    probe = require_probe_headers(request, db)
    if probe.id != probe_id:
        raise HTTPException(403, "probe id mismatch")
    tasks = []
    for target in payload.targets:
        task = create_task(db, "scan", {
            "target": target, "discovery": payload.discovery, "top_ports": payload.top_ports,
            "public_exposed": False, "nuclei": payload.nuclei, "nuclei_tags": payload.nuclei_tags,
            "nuclei_templates": payload.nuclei_templates, "probe_id": probe_id,
        })
        _dispatch(task.id, NETWORK_SCAN)
        tasks.append(serialize_task(task))
    return {"tasks": tasks}




@router.get("/tasks")
def list_tasks(status: str | None = None, kind: str | None = None, search: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    expire_probe_tasks(db)
    db.commit()
    query = select(Task).where(visible_tasks())
    if status:
        query = query.where(Task.status == status)
    if kind:
        query = query.where(Task.kind == kind)
    if search:
        query = query.where(or_(Task.kind.ilike(f"%{search}%"), Task.current_stage.ilike(f"%{search}%"), Task.error.ilike(f"%{search}%")))
    result = paginate(db, query.order_by(Task.id.desc()), page, page_size)
    return page_response([serialize_task(item) for item in result["items"]], page, page_size, result["total"])


@router.post("/tasks")
def create_generic_task(payload: TaskCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, payload.kind, payload.payload)
    return serialize_task(task)


@router.get("/tasks/{task_id}")
def task_detail(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = db.get(Task, task_id)
    if not task or task.payload.get("deleted"):
        raise HTTPException(404, "task not found")
    return serialize_task(task)


@router.post("/tasks/{task_id}/stop", dependencies=[Depends(require_active_admin)])
def stop_task(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = db.scalar(select(Task).where(Task.id == task_id).with_for_update())
    if not task or task.payload.get("deleted"):
        raise HTTPException(404, "任务不存在")
    if task.kind not in PROBE_TASK_KINDS:
        raise HTTPException(409, "当前仅支持停止探针扫描和数据资产采集任务")
    if task.status not in TERMINAL:
        task.status, task.current_stage = "Cancelled", "已停止；已领取任务由探针检查后退出"
        task.finished_at = datetime.now(UTC)
        db.commit()
    return serialize_task(task)


@router.delete("/tasks/{task_id}", dependencies=[Depends(require_active_admin)])
def delete_task(task_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    task = db.scalar(select(Task).where(Task.id == task_id).with_for_update())
    if not task or task.payload.get("deleted"):
        raise HTTPException(404, "任务不存在")
    if task.status not in TERMINAL:
        raise HTTPException(409, "请先停止任务，或等待任务完成后再删除")
    # Keep a tombstone for late probe reports and linked analysis evidence.
    task.payload = {**task.payload, "deleted": True}
    db.commit()
    return {"status": "ok"}


@router.post("/audit/logs")
def analyze_log(payload: LogAnalysisRequest) -> dict[str, Any]:
    lines = payload.content.splitlines()
    context = DetectionContext(target_type="log", data={}, log_lines=lines)
    pipeline = DetectionPipeline(registry, RiskEngine())
    result = pipeline.run(context)
    return {"log_summary": log_analysis(lines), "findings": [item.to_dict() for item in result.findings], "risk": {"score": result.risk_score, "level": result.risk_level}}


@router.get("/audit/summary")
def audit(db: Session = Depends(get_db)) -> dict[str, Any]:
    assets = [serialize_asset(item) for item in db.scalars(select(Asset)).all()]
    files = [serialize_file(item) for item in db.scalars(select(FileRecord)).all()]
    pcaps = [serialize_pcap(item) for item in db.scalars(select(PcapRecord)).all()]
    anomalies = [serialize_anomaly(item) for item in db.scalars(select(Anomaly)).all()]
    return audit_summary(assets, files, pcaps, anomalies)


@router.post("/reports/generate")
def generate_report(payload: GenerateReportRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    assets = [serialize_asset(item) for item in db.scalars(select(Asset)).all()]
    files = [serialize_file(item) for item in db.scalars(select(FileRecord)).all()]
    pcaps = [serialize_pcap(item) for item in db.scalars(select(PcapRecord)).all()]
    anomalies = [serialize_anomaly(item) for item in db.scalars(select(Anomaly)).all()]
    findings = [_serialize_detection(item) for item in db.scalars(select(DetectionFinding).order_by(DetectionFinding.risk_score.desc())).all()]
    data_assets = [_serialize_data_asset(item) for item in db.scalars(select(DataAsset).order_by(DataAsset.id.desc())).all()]
    incidents = [serialize_incident(item) for item in db.scalars(select(Incident).order_by(Incident.risk_score.desc())).all()]
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




@router.get("/engine/registry")
def engine_registry(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Every detection engine with its real rule inventory and finding count.

    ``rule_count`` is the number of rule files backing the engine and
    ``detection_count`` the findings it has actually produced, so the UI never
    has to guess which ``detection_findings.engine`` value an engine writes --
    the internal engine name and the value stored on a finding are not always
    the same string (for example the built-in rule interpreter is registered as
    ``sigma_log_engine``), and the UI routes predate both.
    """
    # Count each engine's own rule files so the number always matches the rule
    # list the console renders for that engine.
    rule_counts: dict[str, int] = {}
    inventory = rule_file_entries(db, include_content=False)
    for item in inventory:
        rule_key = str(item.get("engine") or "")
        rule_counts[rule_key] = rule_counts.get(rule_key, 0) + 1
    finding_counts = {
        str(name): int(total)
        for name, total in db.execute(
            select(DetectionFinding.engine, func.count(DetectionFinding.id)).group_by(DetectionFinding.engine)
        ).all()
    }
    items: list[dict[str, Any]] = []
    for engine in registry.all():
        entry = dict(engine.metadata())
        name = str(entry.get("name") or "")
        slug, label = ENGINE_PRESENTATION.get(name, (name, name))
        rule_count = rule_counts.get(name)
        source = next((item for item in CATALOG if item.engine == name), None)
        entry.update({
            "slug": slug,
            "label": label,
            "rule_count": int(rule_count or 0),
            "active_rule_files": sum(item['execution'] == 'active' for item in inventory
                                     if item['engine'] == name),
            "rule_source": source.source_name or '平台检查规则' if source else '平台检查规则',
            "refreshable": bool(source and source.refreshable),
            "detection_engine": name,
            "detection_count": finding_counts.get(name, 0),
        })
        items.append(entry)
    return items


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
    return {"detection": _serialize_detection(item), "related_incidents": [serialize_incident(item) for item in incidents], "pcap": serialize_pcap(pcap) if pcap else None, "alert": serialize_alert(alert) if alert else None}


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
    return {"items": [serialize_incident(item) for item in rows]}


@router.get("/dashboard/high-risk-assets")
def dashboard_high_risk_assets(limit: int = Query(10, le=100), db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.scalars(select(Asset).order_by(Asset.risk_level.desc(), Asset.id.desc()).limit(limit)).all()
    return {"items": [serialize_asset(item) for item in rows]}


@router.get("/dashboard/sensitive-data")
def dashboard_sensitive_data(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(DataAsset.sensitivity, func.count(DataAsset.id)).group_by(DataAsset.sensitivity)).all()
    return {"items": [{"category": category, "count": count} for category, count in rows]}


# ---------------------------------------------------------------------------
# Frontend-alignment additions
# ---------------------------------------------------------------------------


@router.get("/flows")
def global_flows(search: str | None = None, ip: str | None = None, protocol: str | None = None, port: int | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Global flow explorer across all captured PCAPs."""
    query = select(Flow)
    if ip:
        query = query.where(or_(Flow.src_ip == ip, Flow.dst_ip == ip))
    if protocol:
        query = query.where(Flow.protocol == protocol)
    if port:
        query = query.where(or_(Flow.src_port == port, Flow.dst_port == port))
    if search:
        query = query.where(or_(Flow.src_ip.ilike(f"%{search}%"), Flow.dst_ip.ilike(f"%{search}%")))
    result = paginate(db, query.order_by(Flow.bytes.desc()), page, page_size)
    return page_response([serialize_flow(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/protocols")
def global_protocols(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Global protocol distribution across all captured PCAPs.

    Every row carries the layer the protocol name belongs to, so the console
    can chart application protocols instead of transport and capture plumbing.
    """
    rows = db.execute(select(Flow.protocol, func.count(Flow.id), func.sum(Flow.bytes)).group_by(Flow.protocol)).all()
    items = [
        {"name": name, "count": count, "bytes": int(bytes or 0), "layer": protocol_layer(name)}
        for name, count, bytes in rows
    ]
    items.sort(key=lambda item: item["count"], reverse=True)
    return items


@router.get("/network/live")
def network_live(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Live traffic overview derived from recent PCAP flows + probe heartbeat."""
    now = datetime.now(UTC)
    window_seconds = 300
    since = now - timedelta(seconds=window_seconds)
    recent_pcaps = db.scalars(select(PcapRecord.id).where(PcapRecord.created_at >= since)).all()
    pcap_ids = [item for item in recent_pcaps]
    probes = db.scalars(select(Probe)).all()
    online = 0
    degraded = 0
    cpu: list[float] = []
    mem: list[float] = []
    for probe in probes:
        status = serialize_probe(probe)["status"]
        if status == "online":
            online += 1
        elif status == "degraded":
            degraded += 1
        extra = probe.extra or {}
        system = extra.get("system") or {}
        if isinstance(system.get("cpu_percent"), (int, float)):
            cpu.append(float(system["cpu_percent"]))
        if isinstance(system.get("memory_percent"), (int, float)):
            mem.append(float(system["memory_percent"]))
    flows: list[Flow] = []
    packets: list[PacketRecord] = []
    if pcap_ids:
        flows = list(db.scalars(select(Flow).where(Flow.pcap_id.in_(pcap_ids))).all())
        packets = list(db.scalars(select(PacketRecord).where(PacketRecord.pcap_id.in_(pcap_ids))).all())
    total_bytes = sum(item.bytes for item in flows)
    total_packets = sum(item.packets for item in flows)
    src_counter: Counter[str] = Counter()
    dst_counter: Counter[str] = Counter()
    port_counter: Counter[int] = Counter()
    for flow in flows:
        src_counter[flow.src_ip] += flow.bytes
        dst_counter[flow.dst_ip] += flow.bytes
        port_counter[flow.dst_port] += flow.bytes
    top_src = [{"ip": ip, "bytes": bytes} for ip, bytes in src_counter.most_common(10)]
    top_dst = [{"ip": ip, "bytes": bytes} for ip, bytes in dst_counter.most_common(10)]
    top_port = [{"port": port, "bytes": bytes} for port, bytes in port_counter.most_common(10)]
    recent_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.created_at >= since)) or 0
    return {
        "window_seconds": window_seconds,
        "probes": {"online": online, "degraded": degraded, "total": len(probes)},
        "connections": len(flows),
        "packets": total_packets,
        "bytes": total_bytes,
        "pps": round(total_packets / window_seconds, 2),
        "bps": round(total_bytes / window_seconds, 2),
        "avg_cpu_percent": round(sum(cpu) / len(cpu), 2) if cpu else 0,
        "avg_memory_percent": round(sum(mem) / len(mem), 2) if mem else 0,
        "top_src": top_src,
        "top_dst": top_dst,
        "top_port": top_port,
        "alerts_30m": recent_alerts,
    }


#: Coarse buckets for the two engines that can emit sensitive findings; the
#: per-entity breakdown lives in the object-model ``Detection`` rows instead.


@router.get("/dashboard/incident-trend")
def incident_trend(range: str = Query("7d"), db: Session = Depends(get_db)) -> dict[str, Any]:
    days = 1 if range == "24h" else 7
    since = datetime.now(UTC) - timedelta(days=days)
    rows = db.scalars(select(Incident).where(Incident.created_at >= since).order_by(Incident.created_at)).all()
    buckets: dict[str, dict[str, float | int]] = {}
    for item in rows:
        key = item.created_at.strftime("%Y-%m-%d") if days > 1 else item.created_at.strftime("%Y-%m-%d %H:00")
        entry = buckets.setdefault(key, {"count": 0, "critical": 0, "high": 0, "medium": 0, "risk_score": 0})
        entry["count"] = int(entry["count"]) + 1
        entry["risk_score"] = max(float(entry["risk_score"]), item.risk_score)
        if item.severity == "Critical":
            entry["critical"] = int(entry["critical"]) + 1
        elif item.severity == "High":
            entry["high"] = int(entry["high"]) + 1
        elif item.severity == "Medium":
            entry["medium"] = int(entry["medium"]) + 1
    return {"range": range, "items": [{"time": key, **value} for key, value in sorted(buckets.items())]}


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


@router.get("/probes/{probe_id}/metrics")
def probe_metrics(probe_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    probe = db.get(Probe, probe_id)
    if not probe:
        raise HTTPException(404, "probe not found")
    extra = probe.extra or {}
    system = extra.get("system") or {}
    spool = extra.get("spool_size_mb", 0)
    pending = extra.get("pending_segments", 0)
    quarantined = extra.get("quarantined_segments", 0)
    return {
        "probe": serialize_probe(probe),
        "system": system,
        "cpu_percent": system.get("cpu_percent"),
        "memory_percent": system.get("memory_percent"),
        "memory_rss_mb": system.get("memory_rss_mb") or extra.get("memory_rss_mb"),
        "capture_status": extra.get("capture_status", probe.status),
        "upload_status": extra.get("upload_status", "online"),
        "capture_tool": extra.get("capture_tool", ""),
        "spool_size_mb": spool,
        "pending_segments": pending,
        "quarantined_segments": quarantined,
        "drop_rate": extra.get("drop_rate"),
        "last_capture": extra.get("last_capture", ""),
        "last_upload": extra.get("last_upload", ""),
        "last_seen": _aware(probe.last_seen),
    }


# Legacy asset projection and sensitive findings share a dedicated read boundary.

router.include_router(data_assets_router)
router.include_router(pcaps_router)
router.include_router(files_router)
router.include_router(assets_router)
router.include_router(incidents_router)
router.include_router(alerts_router)
