from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from app.core.config import settings
from app.core.database import SessionLocal
from app.models import Alert, AlertDelivery, DetectionFinding
from app.services.alert_service import (
    alert_fingerprint,
    create_finding_alert,
    event_type_for_status,
    publish_alert,
    queue_deliveries,
)

RULE = "TEST_ALERT_001"


def _make_finding(asset: str = "10.0.0.25", severity: str = "High", risk_score: float = 70) -> DetectionFinding:
    return DetectionFinding(
        target_type="pcap",
        target_id="1",
        engine="test",
        rule_id=RULE,
        severity=severity,
        confidence=0.9,
        evidence={"src_ip": asset},
        recommendation="test",
        risk_score=risk_score,
        risk_level="High",
        timestamp="2026-01-01T00:00:00Z",
    )


def _cleanup() -> None:
    with SessionLocal() as db:
        db.execute(delete(AlertDelivery).where(AlertDelivery.alert_id.in_(select(Alert.id).where(Alert.title.like("%TEST_ALERT%")))))
        db.execute(delete(Alert).where(Alert.fingerprint == alert_fingerprint(RULE, "test", "10.0.0.25", "")))
        db.execute(delete(DetectionFinding).where(DetectionFinding.rule_id == RULE))
        db.commit()


def test_alert_dedup_updates_occurrence() -> None:
    _cleanup()
    with SessionLocal() as db:
        finding = _make_finding()
        db.add(finding)
        db.commit()
        db.refresh(finding)
        first, created1 = create_finding_alert(db, finding)
        db.commit()
        second, created2 = create_finding_alert(db, finding)
        db.commit()
        assert created1 is True
        assert created2 is False
        assert first is not None and second is not None
        assert first.id == second.id
        assert second.occurrence_count >= 2
        assert second.alert_instance == 1
    _cleanup()


def test_resolved_alert_creates_new_instance_after_recurrence() -> None:
    _cleanup()
    with SessionLocal() as db:
        finding = _make_finding()
        db.add(finding)
        db.commit()
        db.refresh(finding)
        first, created1 = create_finding_alert(db, finding)
        db.commit()
        assert created1 is True
        first.status = "resolved"
        db.commit()

        # Within the same instant but resolved: a new instance must appear.
        second, created2 = create_finding_alert(db, finding)
        db.commit()
        assert created2 is True
        assert second is not None
        assert second.id != first.id
        assert second.alert_instance == 2
        assert second.status == "new"
    _cleanup()


def test_alert_expired_suppress_window_creates_new_instance() -> None:
    _cleanup()
    with SessionLocal() as db:
        finding = _make_finding()
        db.add(finding)
        db.commit()
        db.refresh(finding)
        first, _ = create_finding_alert(db, finding)
        db.commit()
        # Rewind last_seen beyond the suppress window.
        first.last_seen = datetime.now(UTC) - timedelta(seconds=settings.alert_suppress_window_seconds + 1)
        db.commit()
        second, created2 = create_finding_alert(db, finding)
        db.commit()
        assert created2 is True
        assert second.id != first.id
    _cleanup()


def test_acknowledged_alert_within_window_suppresses() -> None:
    _cleanup()
    with SessionLocal() as db:
        finding = _make_finding()
        db.add(finding)
        db.commit()
        db.refresh(finding)
        first, _ = create_finding_alert(db, finding)
        first.status = "acknowledged"
        db.commit()
        second, created2 = create_finding_alert(db, finding)
        db.commit()
        assert created2 is False
        assert second.id == first.id
    _cleanup()


def test_queue_deliveries_no_duplicate_channel() -> None:
    _cleanup()
    old_webhook = settings.webhook_url
    settings.webhook_url = "http://example.test/hook"
    settings.smtp_host = ""
    settings.smtp_to = ""
    try:
        with SessionLocal() as db:
            finding = _make_finding()
            db.add(finding)
            db.commit()
            db.refresh(finding)
            alert, _ = create_finding_alert(db, finding)
            db.commit()
            first = queue_deliveries(db, alert.id)
            db.commit()
            second = queue_deliveries(db, alert.id)
            db.commit()
            assert len(first) == 1
            assert len(second) == 1
            rows = db.scalars(select(AlertDelivery).where(AlertDelivery.alert_id == alert.id, AlertDelivery.channel == "webhook", AlertDelivery.status.in_(["pending", "retrying"]))).all()
            assert len(rows) == 1
    finally:
        settings.webhook_url = old_webhook
    _cleanup()


def test_event_type_mapping() -> None:
    assert event_type_for_status("new") == "alert.created"
    assert event_type_for_status("acknowledged") == "alert.acknowledged"
    assert event_type_for_status("resolved") == "alert.resolved"
    assert event_type_for_status("suppressed") == "alert.suppressed"
    assert event_type_for_status("something") == "alert.updated"
