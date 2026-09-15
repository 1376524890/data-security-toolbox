from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.database import SessionLocal
from app.deployment.enrollment import EnrollmentError, consume_enrollment, create_enrollment
from app.models import ProbeDeployment, ProbeEnrollment


def _deployment(idempotency_key: str) -> int:
    with SessionLocal() as db:
        dep = ProbeDeployment(
            name="d",
            host="10.0.0.9",
            username="root",
            auth_type="password",
            profile="standard",
            backend_url="https://platform.local",
            idempotency_key=idempotency_key,
        )
        db.add(dep)
        db.commit()
        db.refresh(dep)
        return dep.id


def test_create_and_consume() -> None:
    dep_id = _deployment("ik-consume")
    with SessionLocal() as db:
        token = create_enrollment(db, db.get(ProbeDeployment, dep_id))
        dep = consume_enrollment(db, dep_id, token, 7)
        db.commit()
        assert dep.id == dep_id
        enrollment = db.scalar(select(ProbeEnrollment).where(ProbeEnrollment.deployment_id == dep_id))
        assert enrollment.consumed_at is not None
        assert enrollment.probe_id == 7


def test_replay_rejected() -> None:
    dep_id = _deployment("ik-replay")
    with SessionLocal() as db:
        token = create_enrollment(db, db.get(ProbeDeployment, dep_id))
        consume_enrollment(db, dep_id, token, 7)
        db.commit()
    with SessionLocal() as db:
        with pytest.raises(EnrollmentError):
            consume_enrollment(db, dep_id, token, 8)
        db.rollback()


def test_wrong_token_rejected() -> None:
    dep_id = _deployment("ik-wrong")
    with SessionLocal() as db:
        create_enrollment(db, db.get(ProbeDeployment, dep_id))
        with pytest.raises(EnrollmentError):
            consume_enrollment(db, dep_id, "not-the-token", 7)
        db.rollback()


def test_expired_rejected() -> None:
    dep_id = _deployment("ik-expired")
    with SessionLocal() as db:
        token = create_enrollment(db, db.get(ProbeDeployment, dep_id), ttl=timedelta(seconds=-1))
        with pytest.raises(EnrollmentError):
            consume_enrollment(db, dep_id, token, 7)
        db.rollback()
