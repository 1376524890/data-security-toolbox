from app.engine.core.context import DetectionContext
from app.engine.traffic_engine.engine import TrafficEngine


def test_port_scan_rule() -> None:
    flows = [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": port, "src_port": 12345, "protocol": "tcp", "packets": 1, "bytes": 60} for port in range(1, 31)]
    context = DetectionContext(target_type="pcap", flows=flows, packets=[])
    findings = TrafficEngine().analyze(context)
    assert any(item.rule_id == "NET_SCAN_001" for item in findings)

