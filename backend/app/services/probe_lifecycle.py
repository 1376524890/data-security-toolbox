"""Retirement of task-dedicated probes.

A probe the task center installs is temporary: its deployment keeps the SSH
credential encrypted (``retain_credential``) precisely so the platform can take
it away again. When the owning task reaches a terminal state and no other
unfinished task still needs that probe, an uninstall deployment is queued; the
removal worker destroys the credential as it finishes.

Two things this refuses to do, because "never delete the wrong thing" outranks
"always clean up": a probe that was registered by hand has no task-owned install
deployment and is never touched, and a host that still has an active deployment
is left for an operator instead of being raced.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deployment.credential import decrypt_credential
from app.deployment.record import DeploymentError
from app.deployment.removal import create_removal_deployment
from app.models import ProbeDeployment, Task
from app.services.task_dispatch import dispatch_probe_deployment

PROBE_TASK_KINDS = ("probe_scan", "data_asset_scan")
TERMINAL = ("Success", "Failed", "Partial", "Cancelled")
RETAIN_FLAG = "retain_credential"


def _reveal(deployment: ProbeDeployment) -> dict[str, Any]:
    """Decrypt the retained credential back into submission form."""
    credential = deployment.credential
    if credential is None:
        raise DeploymentError("CREDENTIAL_MISSING", "credential already destroyed")
    secret = decrypt_credential(deployment.id, deployment.auth_type, credential.key_id,
                                credential.nonce, credential.encrypted_secret)
    if deployment.auth_type != "private_key":
        return {"password": secret, "private_key": None, "key_passphrase": None}
    if secret.startswith("{"):
        data = json.loads(secret)
        return {"password": None, "private_key": data.get("private_key"),
                "key_passphrase": data.get("key_passphrase")}
    return {"password": None, "private_key": secret, "key_passphrase": None}


def owner_deployment(db: Session, probe_id: int) -> ProbeDeployment | None:
    """The successful install deployment that created this probe, if any."""
    return db.scalar(
        select(ProbeDeployment)
        .where(ProbeDeployment.probe_id == probe_id,
               ProbeDeployment.action == "install",
               ProbeDeployment.status == "SUCCEEDED")
        .order_by(ProbeDeployment.id.desc()))


def retire_after_task(db: Session, task: Task) -> int | None:
    """Queue an uninstall for a task-owned probe, or return ``None`` to leave it.

    ``None`` is the answer for: a non-probe task, a task that has not finished, a
    probe another unfinished task still uses, a hand-registered probe, a
    deployment that did not retain its credential, or a host that is busy.
    """
    if task.kind not in PROBE_TASK_KINDS or task.status not in TERMINAL:
        return None
    probe_id = (task.payload or {}).get("probe_id")
    if not probe_id:
        return None
    still_needed = db.scalar(
        select(Task.id).where(Task.kind.in_(PROBE_TASK_KINDS),
                              Task.status.in_(("Pending", "Running")),
                              Task.id != task.id,
                              Task.payload["probe_id"].as_integer() == int(probe_id)))
    if still_needed:
        return None
    deployment = owner_deployment(db, int(probe_id))
    if deployment is None or not (deployment.data_config or {}).get(RETAIN_FLAG):
        return None
    if deployment.credential_destroyed_at is not None or deployment.credential is None:
        return None
    try:
        creds = _reveal(deployment)
        removal = create_removal_deployment(
            db,
            host=deployment.host, port=deployment.port, username=deployment.username,
            auth_type=deployment.auth_type,
            password=creds["password"], private_key=creds["private_key"],
            key_passphrase=creds["key_passphrase"],
            name=f"retire-{probe_id}", idempotency_key=f"retire:{deployment.id}:{task.id}",
            created_by="system", probe_id=int(probe_id),
            # The retired probe removes only what the installer created; the
            # account is left alone so a shared dstprobe survives.
            options={"keep_data": False, "keep_user": True, "remove_user": False,
                     "delete_record": True})
    except DeploymentError:
        # Host busy (or the credential is unusable): leave the probe and let an
        # operator retire it from the deployment list rather than race a removal.
        return None
    db.commit()
    dispatch_probe_deployment(removal.id)
    return removal.id
