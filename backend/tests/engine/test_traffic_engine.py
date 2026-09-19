from app.engine.compliance_engine.engine import ComplianceEngine
from app.engine.core.context import DetectionContext
from app.engine.traffic_engine.engine import TrafficEngine


def _scan_flows() -> list[dict]:
    return [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": port, "src_port": 12345, "protocol": "tcp", "packets": 1, "bytes": 60} for port in range(1, 31)]


def test_port_scan_rule() -> None:
    context = DetectionContext(target_type="pcap", flows=_scan_flows(), packets=[])
    findings = TrafficEngine().analyze(context)
    assert any(item.rule_id == "NET_SCAN_001" for item in findings)


def test_port_scan_rule_counts_one_source_not_the_whole_capture() -> None:
    flows = [{"src_ip": f"10.0.0.{index}", "dst_ip": "10.0.0.2", "dst_port": index,
              "src_port": 12345, "protocol": "tcp", "packets": 1, "bytes": 60}
             for index in range(1, 22)]
    context = DetectionContext(target_type="pcap", flows=flows, packets=[])
    findings = TrafficEngine().analyze(context)
    assert not any(item.rule_id == "NET_SCAN_001" for item in findings)


def test_rule_findings_name_the_engine_that_ran_them() -> None:
    """Rule-driven findings must carry the calling engine's own name.

    The shared rule interpreter used to hard-code ``engine="rules"``: a name no
    engine registers, so network-rule findings were invisible on the traffic
    engine page and the console engine filter could never match them.
    """
    context = DetectionContext(target_type="pcap", flows=_scan_flows(), packets=[])
    findings = TrafficEngine().analyze(context)
    hits = [item for item in findings if item.rule_id == "NET_SCAN_001"]
    assert hits
    assert {item.engine for item in hits} == {"traffic_engine"}


def test_compliance_rules_name_the_compliance_engine() -> None:
    context = DetectionContext(
        target_type="scan",
        assets=[{"ip": "10.0.0.9", "asset_type": "mysql", "public_exposed": True}],
    )
    findings = ComplianceEngine().analyze(context)
    exposed = [item for item in findings if item.rule_id == "COMP_DB_EXPOSURE_001"]
    assert exposed
    assert {item.engine for item in exposed} == {"compliance_engine"}
