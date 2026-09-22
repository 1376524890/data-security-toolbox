"""Contract checks for the 数据安全综合驾驶舱 aggregates.

The cockpit's promise is "a manager can act on every number on this page", and
that needs two properties this file pins down:

* the flat KPI band counts the rows the platform actually stores (never a
  sample, never a projection), and
* the posture ring reports the arithmetic it was computed from, with a
  dimension that has no denominator *absent* rather than scored as a zero that
  would read as a failure.

The third promise - "数据外发" is only claimed when the region table proves the
destination is outside - is checked at the end, because a cockpit that invents
egress is worse than one that stays quiet.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app.api.network_assets import SCAN_SOURCES
from app.core.database import SessionLocal
from app.main import app
from app.models import (
    Alert,
    Asset,
    DataObject,
    DetectionFinding,
    Flow,
    Incident,
    PcapRecord,
    Task,
)
from app.services import egress_regions
from app.services.probe_task_service import COLLECTION_TASK_KINDS

SEED = "COCKPIT_TEST"
PUBLIC_DESTINATION = "203.0.113.9"


def _seed_rows() -> None:
    """Two assets, two data objects, two findings, one incident, one alert."""
    now = datetime.now(UTC)
    with SessionLocal() as db:
        db.add_all([
            Asset(ip="10.60.0.1", hostname=f"{SEED}-host-a", asset_type="server",
                  risk_level="Low", extra={"source": "platform_scan"}, created_at=now),
            Asset(ip="10.60.0.2", hostname=f"{SEED}-host-b", asset_type="database",
                  risk_level="High", extra={"source": "probe_inventory"}, created_at=now),
            DataObject(object_key=f"{SEED}-obj-1", object_type="file",
                       categories=["ID_CARD"], sensitivity="High", created_at=now),
            DataObject(object_key=f"{SEED}-obj-2", object_type="file",
                       categories=[], sensitivity="Low", created_at=now),
            DetectionFinding(target_type="file", target_id=SEED, engine=SEED,
                             rule_id=f"{SEED}_HIGH", severity="High", risk_level="High",
                             confidence=0.9, created_at=now),
            DetectionFinding(target_type="file", target_id=SEED, engine=SEED,
                             rule_id=f"{SEED}_OLD", severity="Low", risk_level="Low",
                             confidence=0.3, created_at=now - timedelta(days=20)),
            Incident(fingerprint=f"{SEED}_INC", title=f"{SEED} 事件", severity="High",
                     risk_level="High", created_at=now),
            Alert(fingerprint=f"{SEED}_ALERT", title=f"{SEED} 告警", severity="High",
                  source=SEED, status="new", created_at=now),
        ])
        db.commit()


def _seed_flows() -> list[str]:
    """One capture with an internal pair and one unprovable destination."""
    now = datetime.now(UTC)
    with SessionLocal() as db:
        pcap = PcapRecord(filename=f"{SEED}.pcap", sha256=f"{SEED}sha", size=512, created_at=now)
        db.add(pcap)
        db.flush()
        ips = ["10.60.0.1", "10.60.0.2", PUBLIC_DESTINATION]
        base = now.timestamp()
        db.add_all([
            Flow(pcap_id=pcap.id, src_ip=ips[0], dst_ip=ips[1], protocol="TCP",
                 packets=4, bytes=400, start_time=base),
            Flow(pcap_id=pcap.id, src_ip=ips[1], dst_ip=ips[0], protocol="TCP",
                 packets=2, bytes=200, start_time=base),
            Flow(pcap_id=pcap.id, src_ip=ips[0], dst_ip=ips[2], protocol="TCP",
                 packets=1, bytes=100, start_time=base),
        ])
        db.commit()
        return ips


def _seed_tasks() -> None:
    with SessionLocal() as db:
        db.add_all([
            Task(kind=COLLECTION_TASK_KINDS[0], status="Completed", current_stage=f"{SEED}-newest"),
            Task(kind="file_source_scan", status="Failed", current_stage=f"{SEED}-older"),
            Task(kind="file_source_scan", status="Completed", current_stage=f"{SEED}-deleted",
                 payload={"deleted": True}),
            Task(kind="pcap", status="Completed", current_stage=f"{SEED}-segment",
                 payload={"monitor_task_id": 1}),
        ])
        db.commit()


def _cleanup() -> None:
    with SessionLocal() as db:
        pcap_ids = select(PcapRecord.id).where(PcapRecord.filename.like(f"{SEED}%"))
        db.execute(delete(Flow).where(Flow.pcap_id.in_(pcap_ids)))
        db.execute(delete(PcapRecord).where(PcapRecord.id.in_(pcap_ids)))
        db.execute(delete(DetectionFinding).where(DetectionFinding.engine == SEED))
        db.execute(delete(Alert).where(Alert.fingerprint == f"{SEED}_ALERT"))
        db.execute(delete(Incident).where(Incident.fingerprint == f"{SEED}_INC"))
        db.execute(delete(DataObject).where(DataObject.object_key.like(f"{SEED}%")))
        db.execute(delete(Asset).where(Asset.hostname.like(f"{SEED}%")))
        db.execute(delete(Task).where(Task.current_stage.like(f"{SEED}%")))
        db.commit()


def _overview() -> dict:
    with TestClient(app) as client:
        response = client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    return response.json()


def test_kpi_band_counts_the_stored_rows() -> None:
    _cleanup()
    _seed_rows()
    try:
        body = _overview()
        with SessionLocal() as db:
            expected = {
                "asset_count": db.scalar(select(func.count(Asset.id))),
                "data_asset_count": db.scalar(select(func.count(DataObject.id))),
                "finding_count": db.scalar(select(func.count(DetectionFinding.id))),
                "incident_count": db.scalar(select(func.count(Incident.id))),
                "alert_count": db.scalar(select(func.count(Alert.id))),
                "network_asset_count": db.scalar(
                    select(func.count(Asset.id))
                    .where(Asset.extra["source"].as_string().in_(SCAN_SOURCES))
                ),
                "high_risk_count": db.scalar(
                    select(func.count(DetectionFinding.id))
                    .where(DetectionFinding.risk_level.in_(["Critical", "High"]))
                ),
            }
        for key, value in expected.items():
            assert body[key] == value, key
        # The seeded High-risk asset is a real one, so the ring has a denominator.
        assert body["asset_count"] >= 2
        assert body["high_risk_count"] >= 1
        assert body["asset_distribution"]["total_assets"] == body["asset_count"]
        assert body["asset_distribution"]["total_network_assets"] == body["network_asset_count"]
        assert body["risk_distribution"]["total_findings"] == body["finding_count"]
    finally:
        _cleanup()


def test_kpi_trends_carry_a_week_window_not_a_bare_number() -> None:
    _cleanup()
    _seed_rows()
    try:
        body = _overview()
        trends = body["trends"]
        for key in ("asset_count", "data_asset_count", "network_asset_count", "finding_count",
                    "incident_count", "alert_count", "high_risk_count", "egress_event_count"):
            window = trends[key]
            assert window["week"] >= 1 or key == "egress_event_count", key
            assert window["prev_week"] >= 0
            assert window["delta_pct"] is None or isinstance(window["delta_pct"], int)
        # The finding seeded three weeks ago is in neither window.
        assert trends["finding_count"]["week"] >= 1
        assert trends["finding_count"]["prev_week"] == 0
        assert trends["finding_count"]["delta_pct"] is None
    finally:
        _cleanup()


def test_posture_ring_reports_the_arithmetic_behind_every_sub_score() -> None:
    _cleanup()
    _seed_rows()
    try:
        body = _overview()
        posture = body["health_score"]
        components = {item["key"]: item for item in posture["components"]}
        assert set(components) == {"asset_safety", "data_protection",
                                   "detection_response", "compliance"}
        for item in posture["components"]:
            if item["key"] == "compliance":
                # A mean of four coverage rates has no single numerator; the
                # board carries the four pairs, so the ring must not invent one.
                assert item["numerator"] is None and item["denominator"] is None
                continue
            assert item["numerator"] >= 0
            assert item["denominator"] >= 0
            if item["denominator"] == 0:
                # No denominator is "unavailable", not a zero score.
                assert item["score"] is None, item["key"]
                assert item["key"] not in posture["weights"]
            else:
                assert item["score"] == round(item["numerator"] * 100 / item["denominator"], 1)
                assert item["key"] in posture["weights"]
        if posture["score"] is not None:
            total_weight = sum(posture["weights"].values())
            expected = round(
                sum(components[key]["score"] * weight
                    for key, weight in posture["weights"].items()) / total_weight, 1
            )
            assert posture["score"] == expected
            assert posture["grade"]
            assert 0 <= posture["score"] <= 100
        # The seeded alert is still "new", so 检测响应 already has a denominator.
        assert components["detection_response"]["denominator"] >= 1
        rates = [item["rate"] for item in body["compliance_progress"]["checks"]
                 if item["rate"] is not None]
        if rates:
            assert components["compliance"]["score"] == round(sum(rates) / len(rates), 1)
        else:
            assert components["compliance"]["score"] is None
    finally:
        _cleanup()


def test_compliance_board_uses_real_denominators() -> None:
    _cleanup()
    _seed_rows()
    try:
        body = _overview()
        board = body["compliance_progress"]
        assert [item["key"] for item in board["checks"]] == [
            "classification", "sensitive_protection", "egress", "permission"]
        for item in board["checks"]:
            if item["denominator"] == 0:
                assert item["rate"] is None, item["key"]
            else:
                assert item["rate"] == round(item["numerator"] * 100 / item["denominator"], 1)
                assert 0 <= item["rate"] <= 100
        rates = [item["rate"] for item in board["checks"] if item["rate"] is not None]
        if rates:
            assert board["rate"] == round(sum(rates) / len(rates), 1)
            assert board["measured"] == len(rates)
            assert board["passed"] == sum(1 for rate in rates if rate >= 100)
        else:
            assert board["rate"] is None
        # The seeded objects include one classified and one not, so the board is
        # reading rows rather than reporting a constant.
        classification = board["checks"][0]
        assert classification["denominator"] >= 2
        assert classification["numerator"] >= 1
    finally:
        _cleanup()


def test_focus_rows_reuse_the_cards_own_windows() -> None:
    _cleanup()
    _seed_rows()
    try:
        body = _overview()
        focus = {item["key"]: item for item in body["focus"]}
        assert list(focus) == ["high_risk", "incidents", "egress", "alerts", "compliance"]
        assert focus["high_risk"]["value"] == body["high_risk_count"]
        assert focus["high_risk"]["delta_pct"] == body["trends"]["high_risk_count"]["delta_pct"]
        assert focus["incidents"]["value"] == body["trends"]["incident_count"]["week"]
        assert focus["egress"]["value"] == body["trends"]["egress_event_count"]["week"]
        assert focus["alerts"]["value"] >= 1
        assert focus["compliance"]["value"] == body["compliance_progress"]["rate"]
    finally:
        _cleanup()


def test_status_rows_pair_every_count_with_its_total() -> None:
    _cleanup()
    _seed_rows()
    try:
        body = _overview()
        rows = {item["key"]: item for item in body["status"]}
        assert list(rows) == ["probes", "integrations", "engines", "collection"]
        for row in body["status"]:
            assert row["total"] >= row["up"] >= 0
            if row["total"] == 0:
                assert row["rate"] is None
            else:
                assert row["rate"] == round(row["up"] * 100 / row["total"], 1)
        # Engines are listed from the registry, so the denominator is never zero.
        assert rows["engines"]["total"] >= 5
        assert rows["integrations"]["total"] == body["integrations"]["total"]
    finally:
        _cleanup()


def test_trend_axis_is_zero_filled_and_flow_days_come_from_the_capture() -> None:
    _cleanup()
    _seed_rows()
    _seed_flows()
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/trend?range=7d").json()
        assert len(body["items"]) == 7
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        assert body["items"][-1]["time"] == today
        for item in body["items"]:
            for key in ("findings", "incidents", "alerts", "internal", "external", "unknown"):
                assert isinstance(item[key], int), key
        assert body["items"][-1]["findings"] >= 1
        # Two of the three sessions are address-to-address inside the private
        # range; the third one cannot be proven to have left, so it is unknown.
        assert body["items"][-1]["internal"] >= 2
        if not egress_regions.table_present():
            assert body["items"][-1]["external"] == 0
            assert body["items"][-1]["unknown"] >= 1
        with TestClient(app) as client:
            hourly = client.get("/api/v1/dashboard/trend?range=24h").json()
        assert len(hourly["items"]) == 24
        assert hourly["items"][-1]["time"].endswith(":00")
    finally:
        _cleanup()


def test_egress_is_only_claimed_when_the_destination_is_proven_outside() -> None:
    _cleanup()
    _seed_flows()
    try:
        body = _overview()
        totals = body["flow"]["totals"]
        assert totals["internal"]["sessions"] >= 2
        assert sum(item["destinations"] for item in totals.values()) >= 2
        if not egress_regions.table_present():
            assert body["egress_event_count"] == 0
            assert totals["unknown"]["sessions"] >= 1
        else:
            assert body["egress_event_count"] == totals["external"]["sessions"]
        assert sum(item["sessions"] for item in totals.values()) >= 3
    finally:
        _cleanup()


def test_recent_tasks_hide_deleted_and_capture_segment_rows() -> None:
    _cleanup()
    _seed_tasks()
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/tasks?limit=50").json()
        stages = [item["current_stage"] for item in body["items"]]
        assert f"{SEED}-newest" in stages
        assert f"{SEED}-older" in stages
        assert f"{SEED}-deleted" not in stages
        assert f"{SEED}-segment" not in stages
        ids = [item["id"] for item in body["items"]]
        assert ids == sorted(ids, reverse=True)
        with TestClient(app) as client:
            limited = client.get("/api/v1/dashboard/tasks?limit=1").json()
        assert len(limited["items"]) == 1
        assert limited["items"][0]["id"] == ids[0]
    finally:
        _cleanup()
