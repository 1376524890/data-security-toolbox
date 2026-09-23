"""A wedged analysis must end up Failed, not sit in Running forever.

A worker killed mid-run (restart, OOM, a third-party binary that never returns)
cannot write its own failure: the task row keeps ``Running`` and the segment
record keeps ``pending``, so the console shows a busy queue that never drains and
the record can never be told apart from one still being worked on.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete

from app.core.database import SessionLocal
from app.models import PcapRecord, Task
from app.workers.maintenance_tasks import STALE_ANALYSIS_SECONDS, sweep_stale_analyses_task

STALE_AT = datetime.now(UTC) - timedelta(seconds=STALE_ANALYSIS_SECONDS + 60)


def _cleanup(ids: list[int]) -> None:
    with SessionLocal() as db:
        db.execute(delete(PcapRecord).where(PcapRecord.id.in_(ids)))
        db.execute(delete(Task).where(Task.payload["pcap_id"].as_integer().in_(ids)))
        db.commit()


def test_a_wedged_analysis_is_closed_as_failed() -> None:
    with SessionLocal() as db:
        stale_record = PcapRecord(
            segment_id=f"sweep-stale-{int(STALE_AT.timestamp())}",
            sequence=1,
            capture_interface="wlan0",
            capture_started_at="2026-01-01T00:00:00Z",
            capture_finished_at="2026-01-01T00:00:30Z",
            ingest_status="ingested",
            analysis_status="pending",
            probe_metadata={},
            filename="stale.pcapng",
            storage_path="/tmp/stale.pcapng",
            size=272,
            sha256="a" * 64,
        )
        done_record = PcapRecord(
            segment_id=f"sweep-done-{int(STALE_AT.timestamp())}",
            sequence=2,
            capture_interface="wlan0",
            capture_started_at="2026-01-01T00:00:00Z",
            capture_finished_at="2026-01-01T00:00:30Z",
            ingest_status="ingested",
            analysis_status="analyzed",
            probe_metadata={},
            filename="done.pcapng",
            storage_path="/tmp/done.pcapng",
            size=272,
            sha256="b" * 64,
        )
        db.add_all([stale_record, done_record])
        db.flush()
        stale_task = Task(kind="pcap", status="Running", payload={"pcap_id": stale_record.id})
        done_task = Task(kind="pcap", status="Running", payload={"pcap_id": done_record.id})
        fresh_task = Task(kind="pcap", status="Running", payload={"pcap_id": stale_record.id})
        db.add_all([stale_task, done_task, fresh_task])
        db.flush()
        # Only the first two are wedged; the third is a live analysis and must
        # survive, which is what keeps the sweep from cancelling real work.
        stale_task.updated_at = STALE_AT
        done_task.updated_at = STALE_AT
        db.commit()
        stale_id, done_id, fresh_id = stale_task.id, done_task.id, fresh_task.id
        record_ids = [stale_record.id, done_record.id]

    try:
        result = sweep_stale_analyses_task()
        assert result["tasks"] >= 2
        with SessionLocal() as db:
            assert db.get(Task, stale_id).status == "Failed"
            assert db.get(Task, done_id).status == "Failed"
            assert db.get(Task, fresh_id).status == "Running"
            assert db.get(Task, stale_id).finished_at is not None
            # A record that already finished is not repainted as a failure.
            assert db.get(PcapRecord, record_ids[0]).analysis_status == "failed"
            assert db.get(PcapRecord, record_ids[1]).analysis_status == "analyzed"
    finally:
        _cleanup(record_ids)


def test_the_sweep_only_touches_running_rows() -> None:
    """A queued task is waiting for a worker, not wedged, however old it is."""
    with SessionLocal() as db:
        pending = Task(kind="pcap", status="Pending", payload={"pcap_id": 10 ** 9})
        db.add(pending)
        db.flush()
        pending.updated_at = STALE_AT
        db.commit()
        pending_id = pending.id
    try:
        sweep_stale_analyses_task()
        with SessionLocal() as db:
            assert db.get(Task, pending_id).status == "Pending"
    finally:
        with SessionLocal() as db:
            db.execute(delete(Task).where(Task.id == pending_id))
            db.commit()


def test_orphan_pending_rows_are_closed_as_evicted() -> None:
    """Rows evicted before ``release`` learned to close them are reconciled here.

    Their file is already gone, so no worker can ever move them off ``pending``.
    """
    with SessionLocal() as db:
        orphan = PcapRecord(
            segment_id=f"sweep-orphan-{int(STALE_AT.timestamp())}",
            sequence=1,
            capture_interface="eth0",
            capture_started_at="2026-01-01T00:00:00Z",
            capture_finished_at="2026-01-01T00:00:30Z",
            ingest_status="ingested",
            analysis_status="pending",
            retention_status="retained_analysis",
            probe_metadata={},
            filename="orphan.pcapng",
            storage_path="/tmp/orphan-that-no-longer-exists.pcapng",
            size=65536000,
            sha256="c" * 64,
        )
        db.add(orphan)
        db.commit()
        orphan_id = orphan.id
    try:
        result = sweep_stale_analyses_task()
        assert result["evicted"] >= 1
        with SessionLocal() as db:
            assert db.get(PcapRecord, orphan_id).analysis_status == "evicted"
    finally:
        with SessionLocal() as db:
            db.execute(delete(PcapRecord).where(PcapRecord.id == orphan_id))
            db.commit()
