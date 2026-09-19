"""Shared HTTP authentication; this module does not register routes."""

from datetime import UTC, datetime

from fastapi import HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_session_user, require_probe_headers
from app.models import Task


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


def enforce_queue_backpressure(db: Session) -> None:
    """Refuse a new upload while the analysis queue is already saturated."""
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
