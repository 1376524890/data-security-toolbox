from app.engine.core.result import DetectionResult
from app.incident_engine.engine import IncidentEngine


def test_incident_requires_multiple() -> None:
    findings = [DetectionResult(engine="zeek", rule_id="ZEK_DNS_TUNNEL_001", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.1"})]
    assert IncidentEngine().correlate(findings) == []


def test_incident_asset_correlation() -> None:
    findings = [
        DetectionResult(engine="zeek", rule_id="ZEK_DNS_TUNNEL_001", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.1"}),
        DetectionResult(engine="suricata", rule_id="SURICATA_HTTP_UPLOAD_001", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.1"}),
    ]
    incidents = IncidentEngine().correlate(findings)
    assert incidents
    assert incidents[0].evidence["asset"] == "10.0.0.1"


def test_incident_ioc_correlation() -> None:
    findings = [
        DetectionResult(engine="misp", rule_id="MISP_IOC_MATCH_001", severity="High", confidence=0.9, evidence={"ioc": {"value": "evil.example"}}),
        DetectionResult(engine="zeek", rule_id="ZEK_DNS_TUNNEL_001", severity="High", confidence=0.8, evidence={"query": "evil.example"}),
    ]
    incidents = IncidentEngine().correlate(findings)
    assert any(item.evidence.get("ioc") == "evil.example" for item in incidents)


def test_incident_attack_chain() -> None:
    findings = [
        DetectionResult(engine="traffic", rule_id="NET_SCAN_001", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.1"}),
        DetectionResult(engine="suricata", rule_id="SURICATA_HTTP_UPLOAD_001", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.1"}),
        DetectionResult(engine="zeek", rule_id="ZEK_DNS_TUNNEL_001", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.1"}),
    ]
    incidents = IncidentEngine().correlate(findings)
    assert incidents
    assert "recon" in incidents[0].evidence["stages"]


def test_nested_asset_dict_resolves_to_its_address() -> None:
    # The threat-intel engine nests the asset it fired on. Joining ip/hostname/
    # service/port into one label produced a string no asset page could match
    # and split one host into one incident per port.
    findings = [
        DetectionResult(engine="threat_intel", rule_id="CVE_1", severity="High", confidence=0.7, evidence={"asset": {"ip": "10.0.0.7", "hostname": "10.0.0.7", "port": 23, "service": "telnet"}}),
        DetectionResult(engine="threat_intel", rule_id="CVE_2", severity="High", confidence=0.7, evidence={"asset": {"ip": "10.0.0.7", "hostname": "10.0.0.7", "port": 443, "service": "https"}}),
    ]
    incidents = IncidentEngine().correlate(findings)
    assert incidents
    assert incidents[0].evidence["asset"] == "10.0.0.7"
    assert incidents[0].evidence["assets"] == ["10.0.0.7"]


def test_transport_and_metric_spellings_attribute_the_host() -> None:
    # The traffic engine spells the pair ``src``/``dst`` and the rules engine
    # only names the host inside its metric keys; both used to yield "global".
    findings = [
        DetectionResult(engine="traffic_engine", rule_id="NET_PORT_SCAN", severity="High", confidence=0.9, evidence={"src": "10.0.0.1", "dst_ports": [22, 80], "port_count": 2}),
        DetectionResult(engine="rules", rule_id="RULE_SCAN", severity="High", confidence=0.9, evidence={"rule": "端口扫描", "metrics": {"port_count": 25, "src:10.0.0.1:ports": 25}}),
    ]
    incidents = IncidentEngine().correlate(findings)
    assets = {value for item in incidents for value in item.evidence["assets"]}
    assert "10.0.0.1" in assets


def test_multi_host_incident_lists_every_host() -> None:
    findings = [
        DetectionResult(engine="traffic_engine", rule_id="NET_PORT_SCAN", severity="High", confidence=0.9, evidence={"src": "10.0.0.1", "dst": "10.0.0.2"}),
        DetectionResult(engine="rules", rule_id="RULE_SCAN", severity="High", confidence=0.9, evidence={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}),
    ]
    incidents = IncidentEngine().correlate(findings)
    assert incidents
    assert incidents[0].evidence["assets"] == ["10.0.0.1", "10.0.0.2"]


def test_rebuild_attribution_repairs_a_legacy_label() -> None:
    from sqlalchemy import delete, select

    from app.core.database import SessionLocal
    from app.incident_engine.attribution import rebuild_attribution
    from app.models import Incident

    fingerprint = "legacy-attribution-test"
    with SessionLocal() as db:
        db.add(Incident(
            fingerprint=fingerprint,
            source="pipeline",
            title="多事件关联：global",
            severity="High",
            confidence=0.9,
            timestamp="2026-01-01T00:05:00Z",
            risk_score=60.0,
            risk_level="High",
            findings={"items": [
                {"engine": "traffic_engine", "rule_id": "NET_PORT_SCAN", "severity": "High", "confidence": 0.9, "timestamp": "2026-01-01T00:00:00Z", "evidence": {"src": "10.9.9.9", "dst_ports": [22, 80]}},
                {"engine": "rules", "rule_id": "RULE_SCAN", "severity": "High", "confidence": 0.9, "timestamp": "2026-01-01T00:05:00Z", "evidence": {"metrics": {"src:10.9.9.9:ports": 25}}},
            ]},
            evidence={"asset": "global"},
        ))
        db.commit()
        try:
            result = rebuild_attribution(db)
            db.commit()
            row = db.scalar(select(Incident).where(Incident.fingerprint == fingerprint))
            assert row is not None
            assert row.evidence["asset"] == "10.9.9.9"
            assert row.evidence["assets"] == ["10.9.9.9"]
            assert "global" not in row.title
            assert row.title.endswith("10.9.9.9")
            assert result["recovered"] >= 1
            assert result["globals_before"] >= 1
        finally:
            db.execute(delete(Incident).where(Incident.fingerprint == fingerprint))
            db.commit()
