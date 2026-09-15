"""One-time enrollment token management for server-side Probe deployment."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.security import hash_token, verify_token
from app.models import ProbeDeployment, ProbeEnrollment

ENROLLMENT_TTL = timedelta(minutes=15)


class EnrollmentError(Exception):
    pass


def create_enrollment(
    db: Session,
    deployment: ProbeDeployment,
    ttl: timedelta = ENROLLMENT_TTL,
) -> str:
    token = secrets.token_urlsafe(32)
    enrollment = db.scalar(
        select(ProbeEnrollment).where(ProbeEnrollment.deployment_id == deployment.id)
    )
    if not enrollment:
        enrollment = ProbeEnrollment(deployment_id=deployment.id)
        db.add(enrollment)
    enrollment.token_hash = hash_token(token)
    enrollment.expires_at = datetime.now(UTC) + ttl
    enrollment.consumed_at = None
    enrollment.probe_id = None
    db.commit()
    return token


def consume_enrollment(
    db: Session,
    deployment_id: int,
    token: str,
    probe_id: int,
) -> ProbeDeployment:
    """Atomically consume a one-time enrollment and bind ``probe_id``.

    The conditional update is executed inside the caller's transaction so the
    Probe creation and enrollment consumption commit (or roll back) together.
    The caller owns the ``commit``.
    """
    if not token:
        raise EnrollmentError("enrollment token required")
    deployment = db.get(ProbeDeployment, deployment_id)
    if not deployment:
        raise EnrollmentError("deployment not found")
    enrollment = db.scalar(
        select(ProbeEnrollment).where(ProbeEnrollment.deployment_id == deployment_id)
    )
    if not enrollment or not verify_token(token, enrollment.token_hash):
        raise EnrollmentError("invalid enrollment token")
    if enrollment.consumed_at is not None:
        raise EnrollmentError("enrollment token already consumed")
    if enrollment.expires_at.replace(tzinfo=UTC) < datetime.now(UTC):
        raise EnrollmentError("enrollment token expired")
    now = datetime.now(UTC)
    result = db.execute(
        update(ProbeEnrollment)
        .where(ProbeEnrollment.id == enrollment.id, ProbeEnrollment.consumed_at.is_(None))
        .values(consumed_at=now, probe_id=probe_id)
    )
    if result.rowcount != 1:
        raise EnrollmentError("enrollment token already consumed")
    return deployment
