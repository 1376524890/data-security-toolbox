"""A segment with no packets must drain instantly and never reach the engines.

Regression: capture on a quiet window (or on a NIC with no link) produced an
empty pcapng every ``segment_seconds``. Suricata does not fail fast on such a
file - it burns its whole ~60 s startup timeout and then raises - and that
exception aborted the run, left ``analysis_status`` at ``pending`` and held a
pcap worker the whole time. Capture then outran analysis and the backlog grew
without bound, which is the freeze this guards against.
"""
from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app.core.database import SessionLocal
from app.main import app
from app.models import AnalysisResult, DetectionFinding, PcapRecord, Task
from tests.fixtures.generate_empty_capture import write_empty_capture


def _cleanup(segment_id: str) -> None:
    with SessionLocal() as db:
        pcap_ids = list(
            db.scalars(select(PcapRecord.id).where(PcapRecord.segment_id == segment_id)).all()
        )
        if pcap_ids:
            task_ids = list(
                db.scalars(
                    select(Task.id).where(Task.payload["pcap_id"].as_integer().in_(pcap_ids))
                ).all()
            )
            if task_ids:
                db.execute(delete(AnalysisResult).where(AnalysisResult.task_id.in_(task_ids)))
                db.execute(delete(Task).where(Task.id.in_(task_ids)))
            db.execute(delete(PcapRecord).where(PcapRecord.id.in_(pcap_ids)))
        db.commit()


def test_empty_capture_is_analyzed_without_invoking_the_engines(tmp_path: Path) -> None:
    segment_id = f"empty-{int(time.time() * 1000)}"
    _cleanup(segment_id)
    pcap = write_empty_capture(tmp_path / "empty.pcapng")
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/pcaps/upload",
            files={"file": ("empty.pcapng", pcap.read_bytes(), "application/octet-stream")},
            data={
                "metadata_json": '{"segment_id":"'
                + segment_id
                + '","sequence":1,"interface":"wlan0",'
                '"capture_started_at":"2026-01-01T00:00:00Z",'
                '"capture_finished_at":"2026-01-01T00:00:30Z"}'
            },
        )
        assert response.status_code == 200
        pcap_id = response.json()["id"]

    with SessionLocal() as db:
        record = db.get(PcapRecord, pcap_id)
        assert record is not None
        assert record.packet_count == 0
        # The empty window is a finished analysis, not a stuck one: leaving it
        # at ``pending`` is what let the backlog grow.
        assert record.analysis_status == "analyzed"
        task = db.scalar(select(Task).where(Task.payload["pcap_id"].as_integer() == pcap_id))
        assert task is not None
        assert task.status == "Success"
        modules = set(
            db.scalars(select(AnalysisResult.module).where(AnalysisResult.task_id == task.id)).all()
        )
        assert "capture" in modules
        # No engine ran, so none of them could fail or be paid for.
        assert "engine_error" not in modules
        assert not db.scalars(
            select(DetectionFinding.id).where(
                DetectionFinding.target_type == "pcap", DetectionFinding.target_id == str(pcap_id)
            )
        ).all()
        assert db.scalar(
            select(func.count(PcapRecord.id)).where(PcapRecord.segment_id == segment_id)
        ) == 1
    _cleanup(segment_id)
