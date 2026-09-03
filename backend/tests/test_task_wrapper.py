from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import delete, func, select

from app.core.database import SessionLocal
from app.models import Alert, DetectionFinding, Flow, PcapRecord, Task
from app.workers.tasks import analyze_pcap_task, create_task
from tests.fixtures.generate_scan_pcap import write_scan_pcap


def _cleanup() -> None:
    with SessionLocal() as db:
        db.execute(delete(Flow).where(Flow.pcap_id.in_(select(PcapRecord.id).where(PcapRecord.segment_id.like("taskwrapper-%")))))
        db.execute(delete(Alert).where(Alert.finding_id.in_(select(DetectionFinding.id).where(DetectionFinding.target_type == "pcap", DetectionFinding.target_id.in_(select(PcapRecord.id).where(PcapRecord.segment_id.like("taskwrapper-%")))))))
        db.execute(delete(DetectionFinding).where(DetectionFinding.target_type == "pcap", DetectionFinding.target_id.in_(select(PcapRecord.id).where(PcapRecord.segment_id.like("taskwrapper-%")))))
        db.execute(delete(Task).where(Task.payload["pcap_id"].as_integer().in_(select(PcapRecord.id).where(PcapRecord.segment_id.like("taskwrapper-%")))))
        db.execute(delete(PcapRecord).where(PcapRecord.segment_id.like("taskwrapper-%")))
        db.commit()


def test_task_exception_marks_failed(tmp_path: Path) -> None:
    _cleanup()
    corrupt = tmp_path / "corrupt.pcap"
    corrupt.write_bytes(b"\x00\x01\x02\x03not-a-real-pcap" * 10)
    with SessionLocal() as db:
        record = PcapRecord(probe_id=None, segment_id="taskwrapper-corrupt", filename=corrupt.name, storage_path=str(corrupt), size=corrupt.stat().st_size, sha256="deadbeef", ingest_status="ingested", analysis_status="pending")
        db.add(record)
        db.commit()
        db.refresh(record)
        task = create_task(db, "pcap", {"pcap_id": record.id})
    with pytest.raises(Exception):
        analyze_pcap_task(record.id, task.id)
    with SessionLocal() as db:
        updated = db.get(Task, task.id)
        assert updated.status == "Failed"
        assert updated.finished_at is not None
        assert updated.current_stage == "failed"
        assert updated.error
    _cleanup()


def test_pcap_reanalysis_does_not_duplicate(tmp_path: Path) -> None:
    _cleanup()
    segment_id = "taskwrapper-reanalyze"
    pcap = write_scan_pcap(tmp_path / "scan.pcap", ports=30)
    with SessionLocal() as db:
        record = PcapRecord(probe_id=None, segment_id=segment_id, filename=pcap.name, storage_path=str(pcap), size=pcap.stat().st_size, sha256="abcd", ingest_status="ingested", analysis_status="pending")
        db.add(record)
        db.commit()
        db.refresh(record)
        task1 = create_task(db, "pcap", {"pcap_id": record.id})
        task2 = create_task(db, "pcap", {"pcap_id": record.id})
    analyze_pcap_task(record.id, task1.id)
    with SessionLocal() as db:
        flows1 = db.scalar(select(func.count(Flow.id)).where(Flow.pcap_id == record.id)) or 0
    analyze_pcap_task(record.id, task2.id)
    with SessionLocal() as db:
        flows2 = db.scalar(select(func.count(Flow.id)).where(Flow.pcap_id == record.id)) or 0
        findings = db.scalar(select(func.count(DetectionFinding.id)).where(DetectionFinding.target_type == "pcap", DetectionFinding.target_id == str(record.id))) or 0
    assert flows1 > 0
    assert flows2 == flows1  # not doubled
    assert findings > 0
    _cleanup()
