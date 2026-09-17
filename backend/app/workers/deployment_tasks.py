"""Celery tasks for server-side Probe deployment."""

from __future__ import annotations

import threading
from datetime import UTC, datetime

from celery.utils.log import get_task_logger
from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.deployment.removal import RemovalService
from app.deployment.service import DeploymentService
from app.models import ProbeDeployment
from app.workers.celery_app import celery_app

logger = get_task_logger(__name__)


def dispatch_probe_deployment(deployment_id: int) -> None:
    """Queue a deployment or removal, falling back to in-process execution.

    The fallback keeps the console usable when the broker is unreachable, which
    is exactly the state a half-configured stack is in - and a half-configured
    stack is when an operator most needs to take a probe back off a host. The
    API module keeps its own thin wrapper around this so tests can stub the
    dispatch out without reaching into the worker.
    """
    try:
        run_probe_deployment_task.delay(deployment_id)
    except Exception:
        threading.Thread(target=run_probe_deployment_task.run, args=(deployment_id,), daemon=True).start()


@celery_app.task(name="security_toolbox.run_probe_deployment", queue=settings.deployment_worker_queue)
def run_probe_deployment_task(deployment_id: int) -> None:
    """Execute the SSH push flow for a single deployment row.

    Removal rows use the same queue and the same task as installs; the row's own
    ``action`` picks the service, so a dispatched task can never be replayed
    against the wrong remote step.
    """
    db = SessionLocal()
    try:
        deployment = db.get(ProbeDeployment, deployment_id)
        if deployment is not None and deployment.action == "uninstall":
            RemovalService(db, deployment_id).run()
        else:
            DeploymentService(db, deployment_id).run()
    finally:
        db.close()


@celery_app.task(name="security_toolbox.sweep_deployment_timeouts")
def sweep_deployment_timeouts() -> int:
    """Mark deployments whose registration callback window expired."""
    db = SessionLocal()
    marked = 0
    try:
        now = datetime.now(UTC)
        rows = db.scalars(
            select(ProbeDeployment).where(
                ProbeDeployment.status.in_(["WAIT_CALLBACK", "REGISTERED"]),
                ProbeDeployment.callback_deadline.is_not(None),
                ProbeDeployment.callback_deadline < now,
            )
        ).all()
        for deployment in rows:
            deployment.status = "FAILED"
            deployment.error_code = "CALLBACK_TIMEOUT"
            deployment.error_message = "probe did not complete registration and first heartbeat within the callback window"
            deployment.current_stage = "CALLBACK_TIMEOUT"
            deployment.progress = 100
            marked += 1
        db.commit()
    finally:
        db.close()
    return marked
