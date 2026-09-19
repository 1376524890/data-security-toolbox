# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Probe domain: registration, heartbeat, inventory, metrics and removal.

The HTTP boundary only: probe authentication/ownership comes from
``core/security.py`` and ``api/dependencies.py``, enrolment from
``deployment/enrollment.py``, task rows from ``services/task_service.py`` and the
remote uninstall from ``deployment/removal.py``.  Probe rows are serialised by
the shared ``api/probe_presenter.py``.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.dependencies import dispatch_task
from app.api.pagination import page_response, paginate
from app.api.probe_presenter import serialize_probe
from app.api.task_presenter import serialize_task
from app.core.config import settings
from app.core.database import get_db
from app.core.datetimes import aware
from app.core.security import (
    hash_token,
    require_active_admin,
    require_probe_headers,
    verify_token,
)
from app.deployment.enrollment import EnrollmentError, consume_enrollment
from app.deployment.record import DeploymentError
from app.deployment.removal import create_removal_deployment
from app.models import Probe, ProbeDeployment, Task, User
from app.schemas import Heartbeat, ProbeDeleteRequest, ProbeRegister, ProbeScanRequest
from app.services.crypto_profile import build_crypto_profile
from app.services.probe_service import ProbeInUseError, ProbeNotFoundError, delete_probe_record
from app.services.probe_task_service import expire_probe_tasks, visible_tasks
from app.services.task_dispatch import ANALYZE_ASSETS, NETWORK_SCAN, dispatch_probe_deployment
from app.services.task_service import create_task

router = APIRouter()


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


@router.post("/probes/register")
def register_probe(
    payload: ProbeRegister,
    x_probe_bootstrap_token: str | None = Header(None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
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
            raise HTTPException(401, str(exc)) from exc
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
        probe = Probe(
            name=payload.name,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            extra=payload.metadata,
            status="online",
        )
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
def heartbeat(
    probe_id: int, payload: Heartbeat, request: Request, db: Session = Depends(get_db)
) -> dict[str, str]:
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
def list_probes(
    status: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(Probe)
    if status:
        query = query.where(Probe.status == status)
    if search:
        query = query.where(
            or_(
                Probe.name.ilike(f"%{search}%"),
                Probe.hostname.ilike(f"%{search}%"),
                Probe.ip_address.ilike(f"%{search}%"),
            )
        )
    result = paginate(db, query.order_by(Probe.id.desc()), page, page_size)
    return page_response(
        [serialize_probe(item) for item in result["items"]], page, page_size, result["total"]
    )


def _probe_removal_target(
    db: Session, probe: Probe, payload: ProbeDeleteRequest
) -> tuple[str, int, str]:
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
    dispatch_task(task.id, ANALYZE_ASSETS, probe_id)
    return serialize_task(task)


@router.get("/probes/{probe_id}/tasks")
def probe_tasks(probe_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    expire_probe_tasks(db)
    db.commit()
    tasks = db.scalars(
        select(Task)
        .where(visible_tasks(), Task.payload["probe_id"].as_integer() == probe_id)
        .order_by(Task.id.desc())
        .limit(50)
    ).all()
    return [serialize_task(item) for item in tasks]


@router.get("/crypto/probe-profile")
def crypto_probe_profile(
    probe_id: int = Query(..., ge=1), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Build a probe-derived crypto / password profile for the GB/T 39786
    assessment tool, so the UI can auto-fill its inputs from what the probe
    actually observed (service banners, TLS handshake metadata)."""
    try:
        return build_crypto_profile(db, probe_id)
    except ValueError as exc:
        raise HTTPException(404, "probe not found") from exc


@router.post("/probes/{probe_id}/scan")
def probe_scan(
    probe_id: int, payload: ProbeScanRequest, request: Request, db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Probe-authenticated trigger for automated network environment scanning."""
    probe = require_probe_headers(request, db)
    if probe.id != probe_id:
        raise HTTPException(403, "probe id mismatch")
    tasks = []
    for target in payload.targets:
        task = create_task(
            db,
            "scan",
            {
                "target": target,
                "discovery": payload.discovery,
                "top_ports": payload.top_ports,
                "public_exposed": False,
                "nuclei": payload.nuclei,
                "nuclei_tags": payload.nuclei_tags,
                "nuclei_templates": payload.nuclei_templates,
                "probe_id": probe_id,
            },
        )
        dispatch_task(task.id, NETWORK_SCAN)
        tasks.append(serialize_task(task))
    return {"tasks": tasks}


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
        "last_seen": aware(probe.last_seen),
    }
