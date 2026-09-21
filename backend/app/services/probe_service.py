"""Removing a Probe record from the platform.

Extracted from the API handler so that an operator pressing delete in the
console and a successful remote removal running in the Celery worker follow
exactly the same rules: refuse while work is in flight, keep every collected
record, drop only the identity.

Deleting the record has never touched the target host. What changed is that a
``REMOVED`` deployment now counts as finished, so a probe whose host has been
stripped can be deleted straight away instead of waiting for a deployment that
will never finish.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.services.data_objects import persistence
from app.models import (
    Alert,
    AlertHit,
    Asset,
    FileRecord,
    Incident,
    PcapRecord,
    Probe,
    ProbeDeployment,
    ProbeEnrollment,
    Task,
)
from app.services.probe_task_service import expire_probe_tasks

# A deployment in any other state is still holding the host, so the record has
# to stay until it settles.
FINISHED_DEPLOYMENT_STATES = {"ONLINE", "FAILED", "CANCELLED", "REMOVED"}


class ProbeNotFoundError(LookupError):
    pass


class ProbeInUseError(Exception):
    """The probe still has work in flight and cannot be dropped yet."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def delete_probe_record(db: Session, probe_id: int) -> dict[str, str]:
    expire_probe_tasks(db)
    probe = db.get(Probe, probe_id)
    if not probe:
        raise ProbeNotFoundError("探针不存在")
    active_task = db.scalar(select(Task.id).where(
        Task.payload["probe_id"].as_integer() == probe_id,
        Task.status.in_(["Pending", "Running"]),
    ).limit(1))
    if active_task:
        raise ProbeInUseError("探针有未完成任务，请等待任务结束后再删除")
    deployments = db.scalars(select(ProbeDeployment).where(or_(
        ProbeDeployment.probe_id == probe_id, ProbeDeployment.id == probe.deployment_id,
    ))).all()
    if any(item.status not in FINISHED_DEPLOYMENT_STATES for item in deployments):
        raise ProbeInUseError("探针部署尚未结束，请等待部署结束后再删除")
    # Preserve collected records and deployment history, clearing foreign keys.
    for model in (Asset, FileRecord, PcapRecord, Incident, Alert, AlertHit, ProbeDeployment, ProbeEnrollment):
        db.execute(update(model).where(model.probe_id == probe_id).values(probe_id=None))
    # Retired sources keep their observations and evidence for historical review.
    persistence.forget_probe(db, probe_id)
    if probe.deployment_id:
        db.execute(update(ProbeEnrollment).where(
            ProbeEnrollment.deployment_id == probe.deployment_id,
        ).values(expires_at=datetime.now(UTC)))
    db.delete(probe)
    db.commit()
    return {"status": "ok"}
