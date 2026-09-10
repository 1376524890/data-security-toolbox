"""Test / demo data lifecycle: import the manual testpack, label it, and clear it.

All imported test data is linked to a single probe named ``test-demo`` so it can
be identified (labeled in the UI) and removed atomically. The frontend uses a
session flag so that refreshing the page clears the imported test data.
"""

from __future__ import annotations

import hashlib
import shutil
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, select

from app.core.config import settings
from app.models import Alert, AlertDelivery, AnalysisResult, Anomaly, Asset, DetectionFinding, FileRecord, Flow, Incident, PacketRecord, PcapRecord, Probe, Task
from app.workers.tasks import analyze_pcap_task, create_task, metadata_task

# The manual testpack is mounted read-only into the backend container.
TESTPACK_DIR = Path("/app/data_security_toolbox_manual_testpack")
TEST_PROBE_NAME = "test-demo"


def _store(src: Path, subdir: str) -> tuple[Path, str, str, int]:
    """Copy a testpack file into the backend storage and return (path, sha256, md5, size)."""
    target_dir = settings.storage_dir / subdir
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{uuid.uuid4().hex}_{src.name}"
    shutil.copyfile(src, target)
    data = target.read_bytes()
    return target, hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest(), len(data)


def import_test_data(db) -> dict[str, Any]:
    """Import the manual testpack: a labeled probe + synthetic files/PCAPs + analysis."""
    probe = db.scalar(select(Probe).where(Probe.name == TEST_PROBE_NAME))
    if not probe:
        probe = Probe(name=TEST_PROBE_NAME, hostname=TEST_PROBE_NAME, ip_address="127.0.0.1", extra={"source": "test"}, status="online")
        db.add(probe)
        db.commit()
        db.refresh(probe)

    files_added = 0
    for folder in ("sensitive_data", "files"):
        folder_path = TESTPACK_DIR / folder
        if not folder_path.exists():
            continue
        for src in sorted(folder_path.iterdir()):
            if not src.is_file():
                continue
            path, sha, md5, size = _store(src, "uploads")
            rec = FileRecord(probe_id=probe.id, name=path.name, path=str(path), size=size, sha256=sha, md5=md5, file_type=src.suffix.lower().lstrip("."), metadata_json={"source": "test"}, risk_level="Low")
            db.add(rec)
            db.flush()
            task = create_task(db, "metadata", {"file_id": rec.id})
            metadata_task.delay(rec.id, task.id)
            files_added += 1

    pcaps_added = 0
    pcap_dir = TESTPACK_DIR / "pcap"
    if pcap_dir.exists():
        for src in sorted(pcap_dir.iterdir()):
            if not src.is_file():
                continue
            path, sha, md5, size = _store(src, "pcaps")
            rec = PcapRecord(probe_id=probe.id, segment_id=f"test-{src.stem}", filename=path.name, storage_path=str(path), size=size, sha256=sha, ingest_status="ingested", analysis_status="pending", probe_metadata={"source": "test"}, sequence=0)
            db.add(rec)
            db.flush()
            task = create_task(db, "pcap", {"pcap_id": rec.id})
            analyze_pcap_task.delay(rec.id, task.id)
            pcaps_added += 1

    db.commit()
    return {"probe_id": probe.id, "probe_name": probe.name, "files": files_added, "pcaps": pcaps_added}


def clear_test_data(db) -> dict[str, Any]:
    """Remove the test-demo probe and everything linked to it."""
    probes = db.scalars(select(Probe).where(Probe.name == TEST_PROBE_NAME)).all()
    ids = [p.id for p in probes]
    removed_probes = len(ids)
    removed_files = 0
    removed_pcaps = 0
    removed_assets = 0
    removed_findings = 0
    if ids:
        # incidents + alerts referencing the test probe must go before the probe
        incident_ids = db.scalars(select(Incident.id).where(Incident.probe_id.in_(ids))).all()
        if incident_ids:
            db.execute(delete(Alert).where(Alert.incident_id.in_(incident_ids)))
            db.execute(delete(Incident).where(Incident.id.in_(incident_ids)))
        task_ids = db.scalars(select(Task.id).where(Task.payload["probe_id"].as_integer().in_(ids))).all()
        finding_ids: list[int] = []
        if task_ids:
            finding_ids = db.scalars(select(DetectionFinding.id).where(DetectionFinding.task_id.in_(task_ids))).all()
            if finding_ids:
                alert_ids = db.scalars(select(Alert.id).where(Alert.finding_id.in_(finding_ids))).all()
                if alert_ids:
                    db.execute(delete(AlertDelivery).where(AlertDelivery.alert_id.in_(alert_ids)))
                    db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
                removed_findings = db.execute(delete(DetectionFinding).where(DetectionFinding.id.in_(finding_ids))).rowcount or 0
            db.execute(delete(AnalysisResult).where(AnalysisResult.task_id.in_(task_ids)))
            db.execute(delete(Task).where(Task.id.in_(task_ids)))
        db.execute(delete(Alert).where(Alert.probe_id.in_(ids)))
        removed_files = db.execute(delete(FileRecord).where(FileRecord.probe_id.in_(ids))).rowcount or 0
        removed_assets = db.execute(delete(Asset).where(Asset.probe_id.in_(ids))).rowcount or 0
        pcap_ids = db.scalars(select(PcapRecord.id).where(PcapRecord.probe_id.in_(ids))).all()
        if pcap_ids:
            db.execute(delete(Flow).where(Flow.pcap_id.in_(pcap_ids)))
            db.execute(delete(PacketRecord).where(PacketRecord.pcap_id.in_(pcap_ids)))
            db.execute(delete(Anomaly).where(Anomaly.pcap_id.in_(pcap_ids)))
            removed_pcaps = db.execute(delete(PcapRecord).where(PcapRecord.probe_id.in_(ids))).rowcount or 0
        for p in probes:
            db.delete(p)
        db.commit()
    return {"removed_probes": removed_probes, "files": removed_files, "pcaps": removed_pcaps, "assets": removed_assets, "findings": removed_findings}


def test_status(db) -> dict[str, Any]:
    """Return whether test data is present and how much."""
    probes = db.scalars(select(Probe).where(Probe.name == TEST_PROBE_NAME)).all()
    ids = [p.id for p in probes]
    present = bool(ids)
    counts = {"probes": len(ids), "files": 0, "pcaps": 0, "assets": 0}
    if ids:
        counts["files"] = db.scalar(select(func.count()).select_from(FileRecord).where(FileRecord.probe_id.in_(ids))) or 0
        counts["pcaps"] = db.scalar(select(func.count()).select_from(PcapRecord).where(PcapRecord.probe_id.in_(ids))) or 0
        counts["assets"] = db.scalar(select(func.count()).select_from(Asset).where(Asset.probe_id.in_(ids))) or 0
    return {"present": present, "probe_ids": ids, **counts}
