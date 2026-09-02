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
