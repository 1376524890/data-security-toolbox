"""Shared bookkeeping for anything driven through a ``ProbeDeployment`` row.

Deployment (install) and removal (uninstall) are the same kind of operation from
the platform's point of view: one SSH push, one credential, one append-only
event log, one status machine. Only the remote step differs. The plumbing that
touches the row lives here so the two services cannot drift apart - the event
sequence, the lease and the credential lifecycle have to behave identically
whichever action produced the row.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.deployment.credential import encrypt_credential
from app.models import ProbeDeployment, ProbeDeploymentCredential, ProbeDeploymentEvent

# Every state in which a row still owns the target host, so a second action
# against the same host has to wait. ``REMOVING`` is in the list for the same
# reason a running install is: one SSH session per host at a time.
ACTIVE_STATUSES = (
    "CREATED",
    "CONNECTING",
    "PREFLIGHT",
    "UPLOADING",
    "INSTALLING",
    "STARTING",
    "REMOVING",
    "WAIT_CALLBACK",
    "REGISTERED",
)


class DeploymentError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _now() -> datetime:
    return datetime.now(UTC)


def store_credential(
    db: Session,
    deployment: ProbeDeployment,
    *,
    auth_type: str,
    password: str | None = None,
    private_key: str | None = None,
    key_passphrase: str | None = None,
    ttl_seconds: int | None = None,
) -> None:
    """Replace the row's credential with an encrypted copy of the supplied one.

    The plaintext lives only in the request and in the worker's memory: it is
    encrypted under the deployment key and bound to the row id, and the worker
    destroys it as soon as a run ends - including a failed one, so a failed
    attempt never leaves a usable secret behind.

    A key passphrase travels inside the same blob as the key because the row
    stores exactly one secret, and the passphrase has to be encrypted with it
    rather than sitting beside it in the clear.
    """
    if deployment.credential:
        db.delete(deployment.credential)
        db.flush()
    secret = password or private_key or ""
    if auth_type == "private_key" and key_passphrase:
        secret = json.dumps({"private_key": private_key, "key_passphrase": key_passphrase})
    ciphertext, nonce, key_id, expires_at = encrypt_credential(
        deployment.id,
        auth_type,
        secret,
        settings.deployment_credential_ttl_seconds if ttl_seconds is None else ttl_seconds,
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


class DeploymentRecord:
    """Mixin over a ``ProbeDeployment`` row; concrete services set these fields."""

    db: Session
    deployment_id: int

    def _load(self) -> ProbeDeployment:
        deployment = self.db.get(ProbeDeployment, self.deployment_id)
        if not deployment:
            raise DeploymentError("NOT_FOUND", "deployment not found")
        return deployment

    def _event(self, deployment: ProbeDeployment, stage: str, message: str) -> None:
        self.db.add(
            ProbeDeploymentEvent(
                deployment_id=deployment.id,
                seq=self._next_event_seq(deployment),
                stage=stage,
                message=message,
            )
        )
        # Sessions run with ``expire_on_commit=False``, so the cached collection
        # keeps whatever it held when it was first loaded: without this, the
        # console polling the row would never see the new event.
        self.db.expire(deployment, ["events"])

    def _next_event_seq(self, deployment: ProbeDeployment) -> int:
        """Next event sequence number for a row.

        Derived from the persisted maximum rather than the length of the loaded
        collection. The collection is a stale snapshot once the session cached
        it (``expire_on_commit=False``) and the flush is not automatic
        (``autoflush=False``), so counting it handed the same sequence to every
        event of a run - the console's ``seq > after`` polling then had nothing
        to advance past.
        """
        self.db.flush()
        highest = self.db.scalar(
            select(func.max(ProbeDeploymentEvent.seq)).where(
                ProbeDeploymentEvent.deployment_id == deployment.id
            )
        )
        return int(highest or 0) + 1

    def _advance(self, deployment: ProbeDeployment, stage: str, progress: int, message: str) -> None:
        deployment.status = stage
        deployment.current_stage = stage
        deployment.progress = progress
        self._event(deployment, stage, message)
        self.db.commit()

    def _fail(self, deployment: ProbeDeployment, code: str, message: str) -> None:
        deployment.status = "FAILED"
        deployment.error_code = code
        deployment.error_message = message[:2000]
        deployment.progress = 100
        self._event(deployment, "FAILED", message)
        self.db.commit()
        self._destroy_credential(deployment)

    def _destroy_credential(self, deployment: ProbeDeployment) -> None:
        if deployment.credential_destroyed_at is not None:
            return
        if deployment.credential:
            self.db.delete(deployment.credential)
        deployment.credential_destroyed_at = _now()
        self.db.commit()

    def _lease(self, deployment: ProbeDeployment) -> None:
        deployment.lease_expires_at = _now() + timedelta(minutes=30)
        deployment.version = (deployment.version or 0) + 1
        self.db.commit()

    def _remote_temp_dir(self, ssh: Any) -> str:
        """Create a per-run temp dir on the target host."""
        rc, out, _ = ssh.exec("mktemp -d /tmp/dstprobe-deploy-XXXXXX 2>/dev/null")
        if rc != 0 or not out.strip():
            raise DeploymentError("INSTALL_FAILED", "unable to create remote temp dir")
        return out.strip().splitlines()[-1]
