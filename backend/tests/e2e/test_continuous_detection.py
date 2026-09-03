from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app.core.database import SessionLocal
from app.main import app
from app.models import Alert, DetectionFinding, Incident, PcapRecord, Task
from app.services.traffic_state import rolling_traffic_state
from tests.fixtures.generate_scan_pcap import write_scan_pcap


def _cleanup(segment_id: str) -> None:
    with SessionLocal() as db:
        db.execute(delete(PcapRecord).where(PcapRecord.segment_id == segment_id))
        db.execute(delete(DetectionFinding).where(DetectionFinding.target_type == "pcap", DetectionFinding.target_id.in_(select(PcapRecord.id).where(PcapRecord.segment_id == segment_id))))
        db.execute(delete(Alert).where(Alert.finding_id.in_(select(DetectionFinding.id).where(DetectionFinding.target_type == "pcap", DetectionFinding.target_id.in_(select(PcapRecord.id).where(PcapRecord.segment_id == segment_id))))))
        db.execute(delete(Incident).where(Incident.evidence["pcap_id"].as_string() == segment_id))
        db.commit()


def test_real_pcap_upload_to_alert_chain(tmp_path: Path) -> None:
    segment_id = f"e2e-{int(Path('/tmp').stat().st_ino)}-{int(time.time())}"
    _cleanup(segment_id)
    rolling_traffic_state.reset()
    pcap = write_scan_pcap(tmp_path / "scan.pcap", ports=30)
    with TestClient(app) as client:
        response = client.post("/api/v1/pcaps/upload", files={"file": ("scan.pcap", pcap.read_bytes(), "application/octet-stream")}, data={"metadata_json": '{"segment_id":"%s","sequence":1,"interface":"lo","capture_started_at":"2026-01-01T00:00:00Z","capture_finished_at":"2026-01-01T00:00:15Z"}' % segment_id})
        assert response.status_code == 200
        body = response.json()
        assert body["duplicate"] is False
        pcap_id = body["id"]

        duplicate = client.post("/api/v1/pcaps/upload", files={"file": ("scan.pcap", pcap.read_bytes(), "application/octet-stream")}, data={"metadata_json": '{"segment_id":"%s","sequence":1,"interface":"lo"}' % segment_id})
        assert duplicate.status_code == 200
        assert duplicate.json()["duplicate"] is True

    with SessionLocal() as db:
        record = db.get(PcapRecord, pcap_id)
        assert record is not None
        assert record.total_packet_count >= 30
        assert record.indexed_packet_count >= 30
        assert record.analysis_status == "analyzed"
        findings = db.scalars(select(DetectionFinding).where(DetectionFinding.target_type == "pcap", DetectionFinding.target_id == str(pcap_id))).all()
        assert any(item.rule_id == "NETWORK_PORT_SCAN" for item in findings)
        incidents = db.scalars(select(Incident).where(Incident.evidence["pcap_id"].as_string() == str(pcap_id))).all()
        assert incidents
        alerts = db.scalars(select(Alert).where(Alert.finding_id.in_([item.id for item in findings]))).all()
        assert alerts
        task_count = db.scalar(select(func.count(Task.id)).where(Task.payload["pcap_id"].as_integer() == pcap_id)) or 0
        assert task_count == 1
        pcap_count = db.scalar(select(func.count(PcapRecord.id)).where(PcapRecord.segment_id == segment_id)) or 0
        assert pcap_count == 1
    _cleanup(segment_id)
