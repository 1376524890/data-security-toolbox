"""Shared HTTP authentication and cross-domain helpers; this module does not register routes."""

from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_session_user, require_probe_headers
from app.models import Task
from app.services import storage_guard
from app.services.task_dispatch import dispatch_task_row


def authenticated_probe(probe_id, request, db):
    probe = require_probe_headers(request, db)
    if not probe or probe.id != probe_id:
        raise HTTPException(403, "probe id mismatch")
    return probe


def upload_probe_id(request: Request, db: Session, form_probe_id: int | None) -> int | None:
    """Probe ownership of an upload: probe headers first, admin session as fallback.

    A probe always uploads for itself; in production an interactive admin may
    still upload on a probe's behalf by naming ``probe_id`` in the form.
    """
    try:
        probe = require_probe_headers(request, db)
        return probe.id if probe else form_probe_id
    except HTTPException:
        if settings.app_env == "production":
            user = get_session_user(db, request)
            if user:
                return form_probe_id
        raise


def dispatch_task(task_id: int, task_name: str, *args: Any) -> None:
    """Queue one of the platform's analysis tasks by its registered name.

    The task row id always travels as the last argument, which is the calling
    convention every worker task keeps.
    """
    dispatch_task_row(task_name, task_id, *args)


def enforce_queue_backpressure(db: Session) -> None:
    """Refuse a new upload while the platform cannot absorb it.

    Two independent reasons to say no, checked cheapest first: the data
    partition is nearly full (a full disk takes Postgres down, so ingest has to
    stop *before* it is full) and the analysis queue is already saturated.
    """
    # The disk floor is checked before the development shortcut, and therefore in
    # every environment: it is a data-safety limit, not a queue-tuning
    # convenience, and a guard that only ever runs in production is a guard that
    # is first exercised on the day it matters.
    blocked = storage_guard.ingest_blocked()
    if blocked:
        raise HTTPException(
            429, blocked, headers={"Retry-After": str(storage_guard.RETRY_AFTER_SECONDS)}
        )
    if settings.app_env == "development":
        return
    pending = db.scalar(select(func.count(Task.id)).where(Task.status == "Pending")) or 0
    oldest = db.scalar(select(func.min(Task.created_at)).where(Task.status == "Pending"))
    oldest_age = (datetime.now(UTC) - oldest).total_seconds() if oldest else 0
    if pending >= settings.queue_pending_max or oldest_age >= settings.queue_oldest_pending_seconds:
        retry = max(5, min(120, int(oldest_age or 5)))
        raise HTTPException(
            429, "analysis queue is congested; retry later", headers={"Retry-After": str(retry)}
        )
