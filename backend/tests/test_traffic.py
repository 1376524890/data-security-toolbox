from pathlib import Path

from app.services.traffic_service import detect_anomalies, external_engine_analysis, traffic_trend


def test_external_engine_without_binaries(tmp_path: Path) -> None:
    result = external_engine_analysis(tmp_path / "missing.pcap", tmp_path / "output")
    assert result == {"engines": []}


def test_detect_port_scan() -> None:
    flows = [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": port, "protocol": "tcp", "bytes": 10, "packets": 1} for port in range(1, 25)]
    anomalies = detect_anomalies(flows, [])
    assert any(item["rule"] == "port_scan" for item in anomalies)


def test_traffic_trend() -> None:
    packets = [{"timestamp": 1, "length": 10, "src_ip": "a", "dst_ip": "b", "protocol": "tcp"}, {"timestamp": 12, "length": 20, "src_ip": "a", "dst_ip": "b", "protocol": "tcp"}]
    trend = traffic_trend(packets, bucket_seconds=10)
    assert len(trend) == 2
    assert trend[0]["packets"] == 1

