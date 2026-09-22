from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from app.core.config import settings
from app.core.database import SessionLocal
from app.models import Alert, AlertDelivery, AlertHit, DetectionFinding
from app.services.alert_service import (
    alert_fingerprint,
    create_finding_alert,
    event_type_for_status,
    list_alert_hits,
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
        stale_ids = select(Alert.id).where(Alert.title.like("%TEST_ALERT%"))
        db.execute(delete(AlertHit).where(AlertHit.alert_id.in_(stale_ids)))
        db.execute(delete(AlertDelivery).where(AlertDelivery.alert_id.in_(select(Alert.id).where(Alert.title.like("%TEST_ALERT%")))))
        db.execute(delete(Alert).where(Alert.fingerprint == alert_fingerprint(RULE, "test", "10.0.0.25", "")))
        db.execute(delete(AlertHit).where(AlertHit.finding_id.in_(select(DetectionFinding.id).where(DetectionFinding.rule_id == RULE))))
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


def test_alert_detail_exposes_the_matched_rule_and_its_content() -> None:
    """An alert must show which rule matched, and on what.

    The detail payload carries the authored rule (title/condition/raw text) so
    the console can render the rule next to the concrete evidence it matched.
    """
    from fastapi.testclient import TestClient

    from app.main import app

    rule_id = "NET_SCAN_001"
    with SessionLocal() as db:
        db.execute(delete(DetectionFinding).where(DetectionFinding.rule_id == rule_id))
        # An earlier test may leave behind an alert with the same
        # (rule, engine, asset, ioc) fingerprint. Creating this finding would
        # then be suppressed into that stale alert whose finding no longer
        # exists, and the detail payload would legitimately carry no rule.
        # Clear it so this test does not depend on execution order.
        stale = db.scalars(select(Alert).where(Alert.fingerprint == alert_fingerprint(rule_id, "traffic_engine", "", ""))).all()
        for row in stale:
            db.execute(delete(AlertDelivery).where(AlertDelivery.alert_id == row.id))
            db.delete(row)
        db.commit()
        finding = DetectionFinding(
            target_type="pcap",
            target_id="1",
            engine="traffic_engine",
            rule_id=rule_id,
            severity="High",
            confidence=0.9,
            evidence={"rule": "端口扫描", "condition": "port_count > 20", "port_count": 26},
            recommendation="排查源 IP",
            risk_score=81,
            risk_level="Critical",
            timestamp="2026-01-01T00:00:00Z",
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        alert, _ = create_finding_alert(db, finding)
        db.commit()
        assert alert is not None
        alert_id = alert.id
    try:
        with TestClient(app) as client:
            body = client.get(f"/api/v1/alerts/{alert_id}").json()
        rule = body["rule"]
        assert body["finding"] is not None
        assert rule is not None
        assert rule["rule_id"] == rule_id
        assert rule["title"] == "端口扫描"
        assert "port_count > 20" in rule["condition"]
        assert rule["engine"] == "traffic_engine"
        assert rule["content"]
    finally:
        with SessionLocal() as db:
            db.execute(delete(Alert).where(Alert.id == alert_id))
            db.execute(delete(DetectionFinding).where(DetectionFinding.rule_id == rule_id))
            db.commit()


def test_alert_detail_reports_no_rule_file_for_code_built_engines() -> None:
    """Rules implemented in engine code have no file; the field stays empty."""
    from fastapi.testclient import TestClient

    from app.main import app

    _cleanup()
    with SessionLocal() as db:
        finding = _make_finding()
        db.add(finding)
        db.commit()
        db.refresh(finding)
        alert, _ = create_finding_alert(db, finding)
        db.commit()
        assert alert is not None
        alert_id = alert.id
    try:
        with TestClient(app) as client:
            body = client.get(f"/api/v1/alerts/{alert_id}").json()
        assert body["rule"] is None
        assert body["finding"]["rule_id"] == RULE
    finally:
        _cleanup()


def _cleanup_rule(rule_id: str) -> None:
    """Drop alerts, hits and findings a targeted test created."""
    with SessionLocal() as db:
        finding_ids = select(DetectionFinding.id).where(DetectionFinding.rule_id == rule_id)
        alert_ids = select(AlertHit.alert_id).where(AlertHit.finding_id.in_(finding_ids))
        db.execute(delete(AlertHit).where(AlertHit.finding_id.in_(finding_ids)))
        db.execute(delete(AlertDelivery).where(AlertDelivery.alert_id.in_(alert_ids)))
        db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
        db.execute(delete(DetectionFinding).where(DetectionFinding.rule_id == rule_id))
        db.commit()


def _rule_finding(rule_id: str, evidence: dict, risk_score: float = 70, timestamp: str = "2026-01-01T00:00:00Z") -> DetectionFinding:
    return DetectionFinding(
        target_type="pcap",
        target_id="1",
        engine="traffic_engine",
        rule_id=rule_id,
        severity="High",
        confidence=0.9,
        evidence=evidence,
        recommendation="test",
        risk_score=risk_score,
        risk_level="High",
        timestamp=timestamp,
    )


def test_two_scan_sources_are_not_suppressed_together() -> None:
    """Different sources must produce independent alerts.

    The old subject resolver ignored ``src`` and the rule engine's ``metrics``,
    so every scan finding resolved to "" and the second source was silently
    folded into the first alert.
    """
    rule_id = "TEST_ALERT_SRC_001"
    _cleanup_rule(rule_id)
    with SessionLocal() as db:
        left = _rule_finding(rule_id, {"metrics": {"src:10.0.0.7:ports_total": 30}})
        right = _rule_finding(rule_id, {"metrics": {"src:10.0.0.9:ports_total": 30}})
        db.add_all([left, right])
        db.commit()
        first, created_first = create_finding_alert(db, left, 1)
        second, created_second = create_finding_alert(db, right, 2)
        db.commit()
        assert created_first is True and created_second is True
        assert first is not None and second is not None
        assert first.id != second.id
        assert first.fingerprint != second.fingerprint
        assert list_alert_hits(db, first.id)[0]["asset"] == "10.0.0.7"
        assert list_alert_hits(db, first.id)[0]["probe_id"] == 1
        assert list_alert_hits(db, second.id)[0]["asset"] == "10.0.0.9"
    _cleanup_rule(rule_id)


def test_repeat_hits_keep_first_latest_and_highest_risk_evidence() -> None:
    rule_id = "TEST_ALERT_HITS_001"
    _cleanup_rule(rule_id)
    with SessionLocal() as db:
        first = _rule_finding(rule_id, {"src_ip": "10.0.0.30"}, risk_score=70, timestamp="2026-01-01T00:00:00Z")
        db.add(first)
        db.commit()
        db.refresh(first)
        alert, created = create_finding_alert(db, first, 5)
        db.commit()
        assert created is True and alert is not None
        latest = _rule_finding(rule_id, {"src_ip": "10.0.0.30"}, risk_score=95, timestamp="2026-01-01T00:05:00Z")
        db.add(latest)
        db.commit()
        db.refresh(latest)
        same, created_again = create_finding_alert(db, latest, 5)
        db.commit()
        assert created_again is False
        assert same is not None and same.id == alert.id
        assert same.occurrence_count == 2
        hits = list_alert_hits(db, alert.id)
        assert [hit["finding_id"] for hit in hits] == [first.id, latest.id]
        assert hits[0]["is_first"] is True and hits[0]["is_latest"] is False
        assert hits[1]["is_latest"] is True and hits[1]["is_highest_risk"] is True
    _cleanup_rule(rule_id)


ORDER_TITLES = ("TEST_ALERT_ORDER_OLD", "TEST_ALERT_ORDER_NEW")


def _cleanup_order_rows() -> None:
    with SessionLocal() as db:
        db.execute(delete(Alert).where(Alert.title.in_(ORDER_TITLES)))
        db.commit()


def test_alert_list_orders_by_time_when_recent_is_requested() -> None:
    """``order=recent`` is what the 态势大屏's 实时安全事件 list reads.

    The console default stays worst-first; the screen needs the newest rows, and
    asking for them through a parameter keeps one list route instead of two that
    could drift apart.
    """
    from fastapi.testclient import TestClient

    from app.main import app

    _cleanup_order_rows()
    now = datetime.now(UTC)
    with SessionLocal() as db:
        db.add(
            Alert(
                fingerprint="TEST_ALERT_ORDER_OLD",
                title=ORDER_TITLES[0],
                severity="High",
                risk_score=99,
                source="test",
                last_seen=now - timedelta(hours=3),
                created_at=now - timedelta(hours=3),
            )
        )
        db.add(
            Alert(
                fingerprint="TEST_ALERT_ORDER_NEW",
                title=ORDER_TITLES[1],
                severity="Medium",
                risk_score=5,
                source="test",
                last_seen=now,
                created_at=now,
            )
        )
        db.commit()
    query = {"page": 1, "page_size": 50, "search": "TEST_ALERT_ORDER"}
    try:
        with TestClient(app) as client:
            recent = client.get("/api/v1/alerts", params={**query, "order": "recent"}).json()
            default = client.get("/api/v1/alerts", params=query).json()
        assert [item["title"] for item in recent["items"]] == list(ORDER_TITLES[::-1])
        assert [item["title"] for item in default["items"]] == list(ORDER_TITLES)
    finally:
        _cleanup_order_rows()
