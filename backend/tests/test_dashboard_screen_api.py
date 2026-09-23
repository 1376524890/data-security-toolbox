"""Contract checks for the 数据安全态势大屏 aggregates.

The screen's whole promise is "no invented numbers", so these tests do two
things: seed rows and prove the endpoint reports exactly what was seeded, and
prove the honest-degrade path — with no region table loaded, a destination is
never reported as 外发, it stays 未识别.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select

from app.core.database import SessionLocal
from app.main import app
from app.models import (
    Alert,
    Asset,
    AssetInstance,
    DataObject,
    Detection,
    DetectionFinding,
    FileSource,
    Flow,
    Incident,
    PcapRecord,
)
from app.services import egress_regions

SEED = "DASHSCREEN_TEST"


def _seed_window_rows() -> None:
    """One alert/incident/finding today and one yesterday."""
    now = datetime.now(UTC)
    with SessionLocal() as db:
        db.add(
            DetectionFinding(
                target_type="pcap",
                target_id=SEED,
                engine=SEED,
                rule_id=f"{SEED}_RULE",
                severity="High",
                risk_level="High",
                confidence=0.9,
                evidence={"src_ip": "10.7.7.7"},
                timestamp=now.isoformat(),
                created_at=now,
            )
        )
        db.add(
            DetectionFinding(
                target_type="pcap",
                target_id=SEED,
                engine=SEED,
                rule_id=f"{SEED}_RULE",
                severity="Low",
                risk_level="Low",
                confidence=0.4,
                evidence={"src_ip": "10.7.7.8"},
                timestamp=(now - timedelta(days=1)).isoformat(),
                created_at=now - timedelta(days=1),
            )
        )
        db.add(
            Alert(
                fingerprint=f"{SEED}_ALERT",
                title=f"{SEED} 告警",
                severity="High",
                source=SEED,
                created_at=now,
            )
        )
        db.add(
            Incident(
                fingerprint=f"{SEED}_INCIDENT",
                title=f"{SEED} 事件",
                severity="High",
                risk_level="High",
                created_at=now - timedelta(days=1),
            )
        )
        db.commit()


def _seed_flow_rows() -> tuple[int, list[str]]:
    """A capture with two internal sessions and one undecidable destination."""
    now = datetime.now(UTC)
    with SessionLocal() as db:
        pcap = PcapRecord(
            filename=f"{SEED}.pcap",
            sha256=f"{SEED}sha",
            size=1024,
            created_at=now,
        )
        db.add(pcap)
        db.flush()
        ips = ["10.9.9.1", "10.9.9.2", "203.0.113.9"]
        db.add_all(
            [
                Flow(
                    pcap_id=pcap.id,
                    src_ip=ips[0],
                    dst_ip=ips[1],
                    protocol="TCP",
                    packets=10,
                    bytes=1000,
                ),
                Flow(
                    pcap_id=pcap.id,
                    src_ip=ips[1],
                    dst_ip=ips[0],
                    protocol="TCP",
                    packets=4,
                    bytes=400,
                ),
                Flow(
                    pcap_id=pcap.id,
                    src_ip=ips[0],
                    dst_ip=ips[2],
                    protocol="TCP",
                    packets=2,
                    bytes=200,
                ),
            ]
        )
        db.commit()
        return pcap.id, ips


def _cleanup() -> None:
    with SessionLocal() as db:
        pcap_ids = select(PcapRecord.id).where(PcapRecord.filename.like(f"{SEED}%"))
        db.execute(delete(Flow).where(Flow.pcap_id.in_(pcap_ids)))
        db.execute(delete(PcapRecord).where(PcapRecord.id.in_(pcap_ids)))
        db.execute(delete(DetectionFinding).where(DetectionFinding.engine == SEED))
        db.execute(delete(Alert).where(Alert.fingerprint == f"{SEED}_ALERT"))
        db.execute(delete(Incident).where(Incident.fingerprint == f"{SEED}_INCIDENT"))
        db.execute(delete(Asset).where(Asset.hostname.like(f"{SEED}%")))
        _cleanup_geo(db)
        db.commit()


def _cleanup_geo(db) -> None:  # type: ignore[no-untyped-def]
    """Everything the geo-map tests seed, in FK order."""
    source_ids = list(db.scalars(select(FileSource.id).where(FileSource.name.like(f"{SEED}%"))))
    object_ids = list(
        db.scalars(select(DataObject.id).where(DataObject.object_key.like(f"{SEED}%")))
    )
    instance_ids = list(
        db.scalars(select(AssetInstance.id).where(AssetInstance.path.like(f"/{SEED}%")))
    )
    if instance_ids:
        db.execute(delete(Detection).where(Detection.instance_id.in_(instance_ids)))
        db.execute(delete(AssetInstance).where(AssetInstance.id.in_(instance_ids)))
    if object_ids:
        db.execute(delete(DataObject).where(DataObject.id.in_(object_ids)))
    if source_ids:
        db.execute(delete(FileSource).where(FileSource.id.in_(source_ids)))


def test_overview_counts_match_the_stored_rows() -> None:
    _cleanup()
    _seed_window_rows()
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/overview").json()
        today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_start = today_start - timedelta(days=1)
        with SessionLocal() as db:
            expected = {
                "alerts": db.scalar(
                    select(func.count(Alert.id)).where(Alert.created_at >= today_start)
                ),
                "findings": db.scalar(
                    select(func.count(DetectionFinding.id)).where(
                        DetectionFinding.created_at >= today_start
                    )
                ),
            }
            expected_yesterday = db.scalar(
                select(func.count(Incident.id)).where(
                    Incident.created_at >= yesterday_start, Incident.created_at < today_start
                )
            )
        assert body["alerts"]["today"] == expected["alerts"]
        assert body["alerts"]["total"] >= 1
        assert body["findings"]["today"] == expected["findings"]
        assert body["findings"]["today"] >= 1
        assert body["incidents"]["yesterday"] == expected_yesterday
        delta = body["incidents"]["delta_pct"]
        assert delta is None or isinstance(delta, int)
        # The KPI band and the closed loop are the same counts, not two sources.
        assert body["loop"]["alerts"] == body["alerts"]["total"]
        assert body["loop"]["findings"] == body["findings"]["total"]
        assert body["loop"]["assets"] == body["assets"]["total"]
        assert body["probes"]["total"] == (
            body["probes"]["online"] + body["probes"]["degraded"] + body["probes"]["offline"]
        )
        assert body["integrations"]["healthy"] <= body["integrations"]["total"]
    finally:
        _cleanup()


def test_traffic_flow_derives_the_topology_from_the_flow_table() -> None:
    _cleanup()
    _pcap_id, ips = _seed_flow_rows()
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/traffic-flow?limit=10&days=7").json()
        assert body["totals"]["internal"] >= 2
        assert body["totals"]["sessions"] >= 3
        node_ids = {node["id"] for node in body["nodes"]}
        assert {f"ip:{ip}" for ip in ips} <= node_ids
        for node in body["nodes"]:
            if node["ip"] in ips:
                assert node["sessions"] >= 1
                assert node["bytes"] >= 0
        link = next(
            item for item in body["links"] if item["src_ip"] == ips[0] and item["dst_ip"] == ips[1]
        )
        assert link["direction"] == "internal"
        assert link["sessions"] == 1
        assert link["bytes"] == 1000
        # 2 internal sessions + 1 undecidable one; nothing may claim "external"
        # while no region table is loaded.
        assert body["totals"]["external"] == 0 or egress_regions.table_present()
        today = body["trend"][-1]
        assert len(body["trend"]) == 7
        assert today["internal"] >= 2
        assert {"internal", "external", "unknown"} <= set(today)
    finally:
        _cleanup()


def test_a_proven_external_destination_is_the_only_red_line(monkeypatch) -> None:
    """Fake the region table verdict: only then may a link read as egress."""
    _cleanup()
    _pcap_id, ips = _seed_flow_rows()
    real_classify = egress_regions.classify

    def fake_classify(ip, *, blacklist, whitelist, internal):  # type: ignore[no-untyped-def]
        if str(ip) == ips[2]:
            return {"bucket": "country", "region": "US", "reason": "地区表命中 US"}
        return real_classify(ip, blacklist=blacklist, whitelist=whitelist, internal=internal)

    monkeypatch.setattr(egress_regions, "classify", fake_classify)
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/traffic-flow?limit=10&days=7").json()
        link = next(item for item in body["links"] if item["dst_ip"] == ips[2])
        assert link["direction"] == "external"
        assert link["bucket"] == "country"
        assert body["totals"]["external"] >= 1
        assert body["trend"][-1]["external"] >= 1
    finally:
        _cleanup()


def _seed_geo_rows() -> dict[str, str]:
    """Two internal destinations, one of which also holds a detected L3 file.

    The second half is what the map colours by: the flow table only says where
    the packets went, the object model says what was on that host.
    """
    now = datetime.now(UTC)
    with SessionLocal() as db:
        pcap = PcapRecord(
            filename=f"{SEED}-geo.pcap", sha256=f"{SEED}geosha", size=1024,
            packet_count=15, status="analyzed", created_at=now, updated_at=now,
        )
        db.add(pcap)
        db.flush()
        db.add_all([
            Flow(pcap_id=pcap.id, src_ip="10.7.7.1", dst_ip="10.7.7.11",
                 protocol="TCP", packets=10, bytes=1000),
            Flow(pcap_id=pcap.id, src_ip="10.7.7.1", dst_ip="10.7.7.12",
                 protocol="TCP", packets=5, bytes=500),
        ])
        source = FileSource(
            name=f"{SEED}-geo-share", protocol="sftp", host="10.7.7.12", port=22,
            root_path="/", created_at=now, updated_at=now,
        )
        db.add(source)
        db.flush()
        obj = DataObject(
            object_key=f"{SEED}-geo-object", object_type="file", size=10,
            categories=["phone"], sensitivity="High", created_at=now, updated_at=now,
        )
        db.add(obj)
        db.flush()
        instance = AssetInstance(
            object_id=obj.id, owner_key=f"file-source:{source.id}", source_kind="file_share",
            path=f"/{SEED}-geo/persons.csv", name="persons.csv", size=10,
            status="ACTIVE", categories=["phone"], created_at=now, updated_at=now,
        )
        db.add(instance)
        db.flush()
        db.add(Detection(
            object_id=obj.id, instance_id=instance.id, source_kind="file_share",
            category="phone", sensitivity_level="L3", severity="High",
            confidence=0.9, hit_count=3, first_seen_at=now, last_seen_at=now,
        ))
        db.commit()
    return {"path": f"/{SEED}-geo/persons.csv", "host": "10.7.7.12"}


def test_geo_map_groups_destinations_and_colours_them_by_detected_level() -> None:
    _cleanup()
    _seed_geo_rows()
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/geo-map").json()
        internal = next(item for item in body["regions"] if item["key"] == "internal")
        # Both seeded destinations are private addresses, so they are one 内网
        # group with their flows added up, not two rows.
        assert internal["hosts"] == 2
        assert internal["sessions"] == 2
        assert internal["bytes"] == 1500
        assert internal["level_counts"]["L3"] == 1
        assert internal["level_counts"][body["unrated_label"]] == 1

        point = next(item for item in body["points"] if item["region"] == "internal")
        assert point["hosts"] == 2
        # The group takes the worst level any of its hosts carries: one host
        # holding L3 data is the fact worth colouring.
        assert point["level"] == "L3"
        assert point["level_label"] == "L3"
        assert point["country"] == ""
        assert point["lat"] is None and point["lon"] is None
        assert point["level_counts"] == {"L3": 1, body["unrated_label"]: 1}
        # Nothing may claim egress while no region table is loaded.
        assert all(item["region"] != "overseas" for item in body["points"])
    finally:
        _cleanup()


def test_geo_map_places_a_classified_destination_and_names_it(monkeypatch) -> None:
    """Fake the region verdict, as the topology test does: only then may a
    destination be called 境外, and only then does the point get coordinates."""
    _cleanup()
    _pcap_id, ips = _seed_flow_rows()
    real_classify = egress_regions.classify

    def fake_classify(ip, *, blacklist, whitelist, internal):  # type: ignore[no-untyped-def]
        if str(ip) == ips[2]:
            return {"bucket": "country", "region": "US", "reason": "地区表命中 US"}
        return real_classify(ip, blacklist=blacklist, whitelist=whitelist, internal=internal)

    monkeypatch.setattr(egress_regions, "classify", fake_classify)
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/geo-map").json()
        overseas = next(item for item in body["regions"] if item["key"] == "overseas")
        assert overseas["hosts"] == 1
        assert overseas["sessions"] == 1
        point = next(item for item in body["points"] if item["region"] == "overseas")
        assert point["country"] == "US"
        assert point["country_name"] == "美国"
        # A label point comes from the shared table, not from the request.
        assert isinstance(point["lat"], float) and isinstance(point["lon"], float)
        assert point["level"] == "" and point["level_label"] == body["unrated_label"]
    finally:
        _cleanup()


def test_geo_map_never_reports_an_unresolved_destination_as_egress() -> None:
    """The honest-degrade path: with no region table, nothing is 境外."""
    _cleanup()
    _pcap_id, _ips = _seed_flow_rows()
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/geo-map").json()
        assert body["country_table_present"] == egress_regions.table_present()
        if not egress_regions.table_present():
            assert all(item["region"] != "overseas" for item in body["points"])
        labels = {region["key"]: region["label"] for region in body["regions"]}
        assert labels == {
            "internal": "内网", "domestic": "国内", "overseas": "境外", "unknown": "未识别",
        }
        # Every drawn point is one of the four regions the panel can render, and
        # the group sizes add back up to the flow rows that produced them.
        assert {item["region"] for item in body["points"]} <= set(labels)
        assert body["totals"]["sessions"] >= 3
        assert body["totals"]["hosts"] == sum(region["hosts"] for region in body["regions"])
    finally:
        _cleanup()


def test_risk_distribution_matches_the_grouped_rows() -> None:
    _cleanup()
    _seed_window_rows()
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/risk-distribution").json()
        levels = {item["level"]: item["count"] for item in body["risk_levels"]}
        # The two seeded findings carry one High and one Low risk level, so both
        # slices have to be present and non-zero on the screen's donut.
        assert levels.get("High", 0) >= 1
        assert levels.get("Low", 0) >= 1
        assert body["total_findings"] >= 2
        assert body["total_assets"] == sum(item["count"] for item in body["asset_types"])
        assert isinstance(body["severity"], list)
    finally:
        _cleanup()


def test_detection_trend_fills_the_whole_window_and_buckets_today() -> None:
    _cleanup()
    _seed_window_rows()
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/dashboard/detection-trend?range=7d").json()
            hourly = client.get("/api/v1/dashboard/detection-trend?range=24h").json()
        assert len(body["items"]) == 7
        assert len(hourly["items"]) == 24
        assert body["items"][-1]["findings"] >= 1
        assert body["items"][-1]["alerts"] >= 1
        # Zero-filled: a day without capture is still a point on the axis.
        assert all({"findings", "incidents", "alerts"} <= set(item) for item in body["items"])
    finally:
        _cleanup()
