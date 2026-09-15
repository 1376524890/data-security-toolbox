"""Admin-only Probe deployment APIs (preflight, create, history, retry)."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.pagination import page_response, paginate
from app.core.config import settings
from app.core.database import get_db
from app.core.security import require_active_admin
from app.deployment.credential import encrypt_credential
from app.deployment.package import list_packages
from app.deployment.preflight import run_preflight
from app.deployment.ssh_client import SshClient, SshError
from app.models import ProbeDeployment, ProbeDeploymentCredential, ProbeDeploymentEvent, User
from app.schemas import ProbeDeploymentCreate, ProbeDeploymentEventOut, ProbeDeploymentOut, ProbeDeploymentPreflightRequest

router = APIRouter(prefix="/api/v1/probe-deployments", tags=["probe-deployments"])


def _now() -> datetime:
    return datetime.now(UTC)


def _event_out(event: ProbeDeploymentEvent) -> dict[str, Any]:
    return {"id": event.id, "seq": event.seq, "stage": event.stage, "message": event.message, "created_at": event.created_at}


def _serialize(deployment: ProbeDeployment) -> dict[str, Any]:
    return {
        "id": deployment.id,
        "name": deployment.name,
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
        "result": deployment.result,
        "created_at": deployment.created_at,
        "updated_at": deployment.updated_at,
    }


def _dispatch(deployment_id: int) -> None:
    from app.workers.deployment_tasks import run_probe_deployment_task

    try:
        run_probe_deployment_task.delay(deployment_id)
    except Exception:
        threading.Thread(target=run_probe_deployment_task.run, args=(deployment_id,), daemon=True).start()


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
    active_statuses = ["CREATED", "CONNECTING", "PREFLIGHT", "UPLOADING", "INSTALLING", "STARTING", "WAIT_CALLBACK", "REGISTERED"]
    active = db.scalar(select(ProbeDeployment).where(ProbeDeployment.host == payload.host, ProbeDeployment.status.in_(active_statuses)))
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
    )
    db.add(deployment)
    db.flush()
    secret = payload.password or payload.private_key or ""
    if payload.auth_type == "private_key" and payload.key_passphrase:
        import json
        secret = json.dumps({"private_key": payload.private_key, "key_passphrase": payload.key_passphrase})
    ciphertext, nonce, key_id, expires_at = encrypt_credential(
        deployment.id,
        deployment.auth_type,
        secret,
        settings.deployment_credential_ttl_seconds,
    )
    db.add(
        ProbeDeploymentCredential(
            deployment_id=deployment.id,
            encrypted_secret=ciphertext,
            nonce=nonce,
            key_id=key_id,
            expires_at=expires_at,
        )
    )
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
        ProbeDeployment.status.notin_(["FAILED", "CANCELLED", "ONLINE"]),
    ))
    if active:
        raise HTTPException(409, "host already has an active deployment")
    if deployment.credential:
        db.delete(deployment.credential)
        db.flush()
    secret = payload.password or payload.private_key or ""
    if payload.auth_type == "private_key" and payload.key_passphrase:
        import json
        secret = json.dumps({"private_key": payload.private_key, "key_passphrase": payload.key_passphrase})
    ciphertext, nonce, key_id, expires_at = encrypt_credential(
        deployment.id,
        payload.auth_type,
        secret,
        settings.deployment_credential_ttl_seconds,
    )
    db.add(
        ProbeDeploymentCredential(
            deployment_id=deployment.id,
            encrypted_secret=ciphertext,
            nonce=nonce,
            key_id=key_id,
            expires_at=expires_at,
        )
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
