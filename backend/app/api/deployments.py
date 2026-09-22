"""Admin-only Probe deployment APIs (preflight, create, removal, history, retry)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.pagination import page_response, paginate
from app.core.config import settings
from app.core.database import get_db
from app.core.security import require_active_admin
from app.deployment.enrollment import create_enrollment
from app.deployment.package import list_packages
from app.deployment.preflight import run_preflight
from app.deployment.record import ACTIVE_STATUSES, DeploymentError, store_credential
from app.deployment.removal import create_removal_deployment
from app.deployment.service import build_probe_toml
from app.deployment.ssh_client import SshClient, SshError
from app.models import Probe, ProbeDeployment, ProbeDeploymentEvent, User
from app.schemas import (
    ProbeDeploymentCreate,
    ProbeDeploymentEventOut,
    ProbeDeploymentOut,
    ProbeDeploymentPreflightRequest,
    ProbeRemovalCreate,
)

router = APIRouter(prefix="/api/v1/probe-deployments", tags=["probe-deployments"])

#: A hand install is driven by a human on the console's clock, not by an SSH
#: push that finishes in seconds, so the one-time token lives long enough to be
#: copied over, not the fifteen minutes an automated enrollment takes.
MANUAL_ENROLLMENT_TTL = timedelta(hours=24)

#: States in which the worker still owns the SSH session. Minting a second
#: enrollment token during these would invalidate the one the running install
#: is about to use, so the hand install waits for the row to settle first.
MANUAL_BLOCKED_STATUSES = ("CONNECTING", "PREFLIGHT", "UPLOADING", "INSTALLING", "STARTING", "REMOVING")

def _now() -> datetime:
    return datetime.now(UTC)


def _event_out(event: ProbeDeploymentEvent) -> dict[str, Any]:
    return {"id": event.id, "seq": event.seq, "stage": event.stage, "message": event.message, "created_at": event.created_at}


def _serialize(deployment: ProbeDeployment) -> dict[str, Any]:
    return {
        "id": deployment.id,
        "name": deployment.name,
        "action": deployment.action,
        "host": deployment.host,
        "port": deployment.port,
        "username": deployment.username,
        "auth_type": deployment.auth_type,
        "profile": deployment.profile,
        "backend_url": deployment.backend_url,
        "status": deployment.status,
        "progress": deployment.progress,
        "current_stage": deployment.current_stage,
        "error_code": deployment.error_code,
        "error_message": deployment.error_message,
        "probe_id": deployment.probe_id,
        "package_version": deployment.package_version,
        "created_by": deployment.created_by,
        "credential_destroyed": deployment.credential_destroyed_at is not None,
        "callback_deadline": deployment.callback_deadline,
        "registered_at": deployment.registered_at,
        "first_heartbeat_at": deployment.first_heartbeat_at,
        "preflight_result": deployment.preflight_result,
        "data_config": deployment.data_config or {},
        "removal_options": deployment.removal_options or {},
        "result": deployment.result,
        "created_at": deployment.created_at,
        "updated_at": deployment.updated_at,
    }


def _dispatch(deployment_id: int) -> None:
    from app.services.task_dispatch import dispatch_probe_deployment

    dispatch_probe_deployment(deployment_id)


@router.get("/packages", response_model=None)
def package_catalog(user: User = Depends(require_active_admin)) -> dict[str, Any]:
    return {"items": list_packages(), "version": settings.probe_agent_version}


@router.post("/preflight", response_model=None)
def preflight(payload: ProbeDeploymentPreflightRequest, request: Request, db: Session = Depends(get_db), user: User = Depends(require_active_admin)) -> dict[str, Any]:
    """Synchronous, non-persisting preflight against a target host."""
    if payload.auth_type == "password" and not settings.deployment_allow_password:
        raise HTTPException(400, "password authentication is disabled")
    if not (payload.backend_url or settings.deployment_backend_url):
        raise HTTPException(400, "deployment backend url not configured")
    ssh = SshClient(
        host=payload.host,
        port=payload.port,
        username=payload.username,
        password=payload.password if payload.auth_type == "password" else None,
        private_key=payload.private_key if payload.auth_type == "private_key" else None,
        key_passphrase=payload.key_passphrase,
        verify_host_key=settings.deployment_verify_host_key,
    )
    try:
        ssh.connect()
        return run_preflight(ssh, payload.profile, backend_url=payload.backend_url or settings.deployment_backend_url)
    except SshError as exc:
        raise HTTPException(502, {"code": exc.code, "message": exc.message}) from exc
    finally:
        ssh.close()


@router.post("", status_code=202, response_model=None)
def create_deployment(payload: ProbeDeploymentCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(require_active_admin)) -> dict[str, Any]:
    """Create a deployment, encrypt its credential, and dispatch the Worker."""
    if payload.auth_type == "password" and not settings.deployment_allow_password:
        raise HTTPException(400, "password authentication is disabled")
    if not (payload.backend_url or settings.deployment_backend_url):
        raise HTTPException(400, "deployment backend url not configured")
    if not settings.deployment_secret_key:
        raise HTTPException(503, "deployment encryption key not configured")
    existing = db.scalar(select(ProbeDeployment).where(ProbeDeployment.idempotency_key == payload.idempotency_key))
    if existing:
        return _serialize(existing)
    active = db.scalar(
        select(ProbeDeployment).where(
            ProbeDeployment.host == payload.host,
            ProbeDeployment.status.in_(ACTIVE_STATUSES),
        )
    )
    if active:
        raise HTTPException(409, "host already has an active deployment")
    deployment = ProbeDeployment(
        name=payload.name,
        host=payload.host,
        port=payload.port,
        username=payload.username,
        auth_type=payload.auth_type,
        profile=payload.profile,
        status="CREATED",
        current_stage="queued",
        created_by=user.username,
        backend_url=payload.backend_url or settings.deployment_backend_url,
        idempotency_key=payload.idempotency_key,
        data_config={
            "paths": payload.data_paths,
            "interval_seconds": payload.data_interval_seconds,
            "max_files": payload.data_max_files,
            "max_depth": payload.data_max_depth,
            "include_databases": payload.data_include_databases,
            # Marks a task-dedicated probe whose credential is kept (encrypted)
            # until the owning task ends, so the platform can retire it itself.
            "retain_credential": payload.retain_credential,
        },
    )
    db.add(deployment)
    db.flush()
    store_credential(
        db,
        deployment,
        auth_type=payload.auth_type,
        password=payload.password,
        private_key=payload.private_key,
        key_passphrase=payload.key_passphrase,
        ttl_seconds=(settings.deployment_retained_credential_ttl_seconds
                     if payload.retain_credential else None),
    )
    db.commit()
    _dispatch(deployment.id)
    return _serialize(deployment)


@router.delete("/{deployment_id}", response_model=None)
def delete_deployment(deployment_id: int, db: Session = Depends(get_db), user: User = Depends(require_active_admin)) -> dict[str, str]:
    """Drop a finished deployment row from the history.

    History cleanup only: it never touches the target host. Taking the probe off
    a host is ``POST /removal``, which is a separate and auditable action, and
    the row it leaves behind is kept so the console can still say what was
    deleted there.
    """
    deployment = db.get(ProbeDeployment, deployment_id)
    if not deployment:
        raise HTTPException(404, "deployment not found")
    if deployment.status in ACTIVE_STATUSES:
        raise HTTPException(409, "deployment is still running")
    db.delete(deployment)
    db.commit()
    return {"status": "ok"}


@router.post("/removal", status_code=202, response_model=None)
def create_removal(payload: ProbeRemovalCreate, db: Session = Depends(get_db), user: User = Depends(require_active_admin)) -> dict[str, Any]:
    """Remove a probe from a target host, and record what was deleted there.

    The row is an ordinary deployment with ``action='uninstall'``, so the
    console gets the same live progress, event log and audit trail it gets for
    an install; only the remote step differs. Credentials are never reused from
    a previous run - the worker destroys them when that run ends - so the
    operator supplies them again, which is what makes a retry safe.
    """
    if payload.auth_type == "password" and not settings.deployment_allow_password:
        raise HTTPException(400, "password authentication is disabled")
    if not settings.deployment_secret_key:
        raise HTTPException(503, "deployment encryption key not configured")
    existing = db.scalar(select(ProbeDeployment).where(ProbeDeployment.idempotency_key == payload.idempotency_key))
    if existing:
        return _serialize(existing)
    if payload.probe_id is not None and db.get(Probe, payload.probe_id) is None:
        raise HTTPException(404, "probe not found")
    try:
        deployment = create_removal_deployment(
            db,
            host=payload.host,
            port=payload.port,
            username=payload.username,
            auth_type=payload.auth_type,
            password=payload.password,
            private_key=payload.private_key,
            key_passphrase=payload.key_passphrase,
            name=payload.name,
            idempotency_key=payload.idempotency_key,
            created_by=user.username,
            probe_id=payload.probe_id,
            options={
                "keep_data": payload.keep_data,
                "keep_user": payload.keep_user,
                "remove_user": payload.remove_user,
                "delete_record": payload.delete_record,
            },
        )
    except DeploymentError as exc:
        raise HTTPException(409, exc.message) from exc
    db.commit()
    _dispatch(deployment.id)
    return _serialize(deployment)


@router.get("", response_model=None)
def list_deployments(
    status: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(require_active_admin),
) -> dict[str, Any]:
    query = select(ProbeDeployment)
    if status:
        query = query.where(ProbeDeployment.status == status)
    if search:
        query = query.where(or_(ProbeDeployment.name.ilike(f"%{search}%"), ProbeDeployment.host.ilike(f"%{search}%")))
    result = paginate(db, query.order_by(ProbeDeployment.id.desc()), page, page_size)
    return page_response([_serialize(item) for item in result["items"]], page, page_size, result["total"])


@router.get("/{deployment_id}", response_model=None)
def deployment_detail(deployment_id: int, db: Session = Depends(get_db), user: User = Depends(require_active_admin)) -> dict[str, Any]:
    deployment = db.get(ProbeDeployment, deployment_id)
    if not deployment:
        raise HTTPException(404, "deployment not found")
    detail = _serialize(deployment)
    detail["events"] = [_event_out(event) for event in deployment.events]
    return detail


@router.get("/{deployment_id}/events", response_model=None)
def deployment_events(
    deployment_id: int,
    after: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_active_admin),
) -> dict[str, Any]:
    deployment = db.get(ProbeDeployment, deployment_id)
    if not deployment:
        raise HTTPException(404, "deployment not found")
    events = db.scalars(
        select(ProbeDeploymentEvent)
        .where(ProbeDeploymentEvent.deployment_id == deployment_id, ProbeDeploymentEvent.seq > after)
        .order_by(ProbeDeploymentEvent.seq)
    ).all()
    return {"items": [_event_out(event) for event in events]}


@router.post("/{deployment_id}/retry", response_model=None)
def retry_deployment(payload: ProbeDeploymentCreate, deployment_id: int, db: Session = Depends(get_db), user: User = Depends(require_active_admin)) -> dict[str, Any]:
    """Retry a failed deployment with freshly supplied credentials."""
    deployment = db.get(ProbeDeployment, deployment_id)
    if not deployment:
        raise HTTPException(404, "deployment not found")
    # A removal is re-run by posting a new removal request, because the
    # credential that would be needed is destroyed when the first run ends.
    if deployment.action != "install":
        raise HTTPException(409, "removal rows cannot be retried as a deployment")
    if deployment.status not in {"FAILED", "CANCELLED"}:
        raise HTTPException(409, "only failed deployments can be retried")
    if payload.host != deployment.host:
        raise HTTPException(400, "retry target must match original host")
    if payload.auth_type == "password" and not settings.deployment_allow_password:
        raise HTTPException(400, "password authentication is disabled")
    if not settings.deployment_secret_key or not settings.deployment_backend_url:
        raise HTTPException(503, "deployment configuration is incomplete")
    active = db.scalar(select(ProbeDeployment).where(
        ProbeDeployment.host == deployment.host,
        ProbeDeployment.id != deployment.id,
        ProbeDeployment.status.notin_(["FAILED", "CANCELLED", "ONLINE", "REMOVED"]),
    ))
    if active:
        raise HTTPException(409, "host already has an active deployment")
    store_credential(
        db,
        deployment,
        auth_type=payload.auth_type,
        password=payload.password,
        private_key=payload.private_key,
        key_passphrase=payload.key_passphrase,
    )
    deployment.callback_deadline = None
    deployment.registered_at = None
    deployment.first_heartbeat_at = None
    deployment.backend_url = settings.deployment_backend_url
    deployment.auth_type = payload.auth_type
    deployment.username = payload.username
    deployment.port = payload.port
    deployment.profile = payload.profile
    deployment.status = "CREATED"
    deployment.current_stage = "queued"
    deployment.error_code = ""
    deployment.error_message = ""
    deployment.credential_destroyed_at = None
    deployment.progress = 0
    db.commit()
    _dispatch(deployment.id)
    return _serialize(deployment)


@router.get("/packages/{version}/{arch}/download", response_model=None)
def download_package(version: str, arch: str, user: User = Depends(require_active_admin)):
    """Serve one probe package artifact so a hand install has something to copy.

    The auto-deploy path pushes this same artifact over SFTP; when SSH from the
    platform is what is blocked, the operator still needs the bytes on the
    target host, and the console is the only place they can get them.
    """
    from fastapi.responses import FileResponse

    from app.deployment.package import PackageError, find_package

    try:
        pkg = find_package(arch, version)
    except PackageError as exc:
        raise HTTPException(404, str(exc)) from exc
    artifact = pkg["artifact"]
    return FileResponse(
        artifact,
        media_type="application/gzip",
        filename=artifact.name,
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.post("/{deployment_id}/manual-bootstrap", response_model=None)
def manual_bootstrap(deployment_id: int, db: Session = Depends(get_db), user: User = Depends(require_active_admin)) -> dict[str, Any]:
    """Mint a hand-install config so a failed auto-deployment can still connect.

    Automatic deployment needs the platform to reach the host over SSH. When
    that path is blocked the operator can install the packaged probe directly;
    this returns a ready ``probe.toml`` carrying a *fresh* one-time enrollment
    token bound to the same deployment row, so the hand-installed probe reports
    back as this task's probe rather than as an unmanaged stranger.
    """
    deployment = db.get(ProbeDeployment, deployment_id)
    if not deployment:
        raise HTTPException(404, "deployment not found")
    if deployment.action != "install":
        raise HTTPException(409, "only install rows can be handed out for a manual install")
    if deployment.probe_id or deployment.registered_at:
        raise HTTPException(409, "该部署已回连，无需手动安装")
    if deployment.status in MANUAL_BLOCKED_STATUSES:
        raise HTTPException(409, "该部署正在自动安装，请等这一轮结束后再手动安装")
    if not settings.deployment_secret_key:
        raise HTTPException(503, "deployment encryption key not configured")
    backend_url = deployment.backend_url or settings.deployment_backend_url
    if not backend_url:
        raise HTTPException(400, "deployment backend url not configured")
    token = create_enrollment(db, deployment, ttl=MANUAL_ENROLLMENT_TTL)
    toml = build_probe_toml(deployment, token, settings.deployment_ca_file or None)
    version = settings.probe_agent_version
    return {
        "deployment_id": deployment.id,
        "backend_url": backend_url,
        "version": version,
        "expires_at": (datetime.now(UTC) + MANUAL_ENROLLMENT_TTL).isoformat(),
        "toml": toml,
        "packages": list_packages(),
        "steps": [
            f"下载并上传探针包 probe-{version}-<arch>.tar.gz 到目标主机，例如 scp 到 /tmp/",
            "解包并写入下方配置：tar -xzf probe-*.tar.gz -C probe-pkg && "
            "install -m600 /dev/stdin probe-pkg/probe.toml <<'TOML' … TOML",
            "执行 sudo bash probe-pkg/install.sh --install-only --config probe-pkg/probe.toml",
            "回本页点「检测回连」；探针注册后此处会显示在线",
        ],
    }
