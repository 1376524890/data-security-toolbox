from __future__ import annotations

from sqlalchemy import delete

from app.core.database import SessionLocal
from app.models import Alert, DetectionFinding
from app.services.alert_service import create_finding_alert


def test_alert_dedup_updates_occurrence() -> None:
    with SessionLocal() as db:
        db.execute(delete(Alert).where(Alert.title == "test-alert-dedup"))
        db.execute(delete(DetectionFinding).where(DetectionFinding.rule_id == "TEST_ALERT_001"))
        db.commit()
        finding = DetectionFinding(
            target_type="pcap",
            target_id="1",
            engine="test",
            rule_id="TEST_ALERT_001",
            severity="High",
            confidence=0.9,
            evidence={"src_ip": "10.0.0.25"},
            recommendation="test",
            risk_score=70,
            risk_level="High",
            timestamp="2026-01-01T00:00:00Z",
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        first = create_finding_alert(db, finding)
        db.commit()
        second = create_finding_alert(db, finding)
        db.commit()
        assert first is not None
        assert second is not None
        assert first.id == second.id
        assert second.occurrence_count >= 2
        db.execute(delete(Alert).where(Alert.id == first.id))
        db.execute(delete(DetectionFinding).where(DetectionFinding.id == finding.id))
        db.commit()
