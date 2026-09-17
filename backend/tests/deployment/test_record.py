"""The bookkeeping shared by installs and removals.

Both services drive the same ``ProbeDeployment`` row through the same status
and event machine, so anything the mixin gets wrong is wrong for a probe being
pushed out and for one being taken away.
"""

import secrets

from sqlalchemy import select

from app.core.database import SessionLocal
from app.deployment.record import DeploymentRecord
from app.models import ProbeDeployment, ProbeDeploymentEvent


class _Recorder(DeploymentRecord):
    """The mixin on its own, without an SSH session or a real remote step."""

    def __init__(self, db, deployment_id: int):
        self.db = db
        self.deployment_id = deployment_id


def _row(db, host: str) -> int:
    """A throwaway row on an address no other test claims.

    The suite shares one database and a row in an active state blocks its host,
    so these rows are removed again by ``_drop`` once a test is done with them.
    """
    row = ProbeDeployment(
        name="record-test",
        host=host,
        username="root",
        auth_type="password",
        idempotency_key=f"record-{secrets.token_hex(8)}",
    )
    db.add(row)
    db.commit()
    return row.id


def _drop(db, deployment_id: int) -> None:
    db.delete(db.get(ProbeDeployment, deployment_id))
    db.commit()


def test_event_sequence_keeps_counting_after_the_collection_is_cached() -> None:
    """Sequences must come from the table, not from the loaded collection.

    Sessions run with ``expire_on_commit=False``, so reading ``deployment``
    once pins a snapshot of its events; counting that snapshot handed the same
    sequence to every later event. The console polls with ``seq > after``, so
    duplicate sequences mean the progress it displays simply stops advancing.
    """
    with SessionLocal() as db:
        deployment_id = _row(db, "10.8.240.11")
        recorder = _Recorder(db, deployment_id)
        deployment = db.get(ProbeDeployment, deployment_id)
        assert list(deployment.events) == []  # cache the empty collection first
        for stage in ("CONNECTING", "UPLOADING", "INSTALLING"):
            recorder._event(deployment, stage, f"at {stage}")
            db.commit()
        seqs = list(
            db.scalars(
                select(ProbeDeploymentEvent.seq)
                .where(ProbeDeploymentEvent.deployment_id == deployment_id)
                .order_by(ProbeDeploymentEvent.id)
            )
        )
        # The collection the API serializes has to catch up as well.
        assert [event.stage for event in deployment.events] == [
            "CONNECTING",
            "UPLOADING",
            "INSTALLING",
        ]
        _drop(db, deployment_id)
    assert seqs == [1, 2, 3]


def test_event_sequence_continues_a_previous_run() -> None:
    """A retry appends to the trail instead of overwriting its history."""
    with SessionLocal() as db:
        deployment_id = _row(db, "10.8.240.12")
        recorder = _Recorder(db, deployment_id)
        deployment = db.get(ProbeDeployment, deployment_id)
        recorder._event(deployment, "CONNECTING", "first attempt")
        db.commit()
        recorder._event(deployment, "FAILED", "first attempt died")
        db.commit()
        recorder._fail(deployment, "INSTALL_FAILED", "connection reset")
        seqs = list(
            db.scalars(
                select(ProbeDeploymentEvent.seq)
                .where(ProbeDeploymentEvent.deployment_id == deployment_id)
                .order_by(ProbeDeploymentEvent.id)
            )
        )
        _drop(db, deployment_id)
    assert seqs == [1, 2, 3]
