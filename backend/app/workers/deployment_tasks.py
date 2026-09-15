"""Celery tasks for server-side Probe deployment."""

from __future__ import annotations

from datetime import UTC, datetime

from celery.utils.log import get_task_logger
from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.deployment.service import DeploymentService
from app.models import ProbeDeployment
from app.workers.celery_app import celery_app

logger = get_task_logger(__name__)


@celery_app.task(name="security_toolbox.run_probe_deployment", queue=settings.deployment_worker_queue)
def run_probe_deployment_task(deployment_id: int) -> None:
    """Execute the full SSH push-deploy flow for a single deployment."""
    db = SessionLocal()
    try:
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
