from pathlib import Path

from app.services.traffic_service import detect_anomalies, traffic_trend


def test_detect_port_scan() -> None:
    flows = [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": port, "protocol": "tcp", "bytes": 10, "packets": 1} for port in range(1, 25)]
    anomalies = detect_anomalies(flows, [])
    assert any(item["rule"] == "NETWORK_PORT_SCAN" for item in anomalies)


def test_many_hosts_one_port_each_is_not_a_scan() -> None:
    flows = [{"src_ip": f"10.0.0.{index}", "dst_ip": "10.0.0.2", "dst_port": index,
              "protocol": "tcp", "bytes": 10, "packets": 1, "start_time": 1.0}
             for index in range(1, 22)]
    assert not any(item["rule"] == "NETWORK_PORT_SCAN" for item in detect_anomalies(flows, []))


def test_ports_spread_over_time_are_not_one_scan() -> None:
    flows = [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": port,
              "protocol": "tcp", "bytes": 10, "packets": 1, "start_time": port * 100.0}
             for port in range(1, 31)]
    assert not any(item["rule"] == "NETWORK_PORT_SCAN" for item in detect_anomalies(flows, []))


def test_traffic_trend() -> None:
    packets = [{"timestamp": 1, "length": 10, "src_ip": "a", "dst_ip": "b", "protocol": "tcp"}, {"timestamp": 12, "length": 20, "src_ip": "a", "dst_ip": "b", "protocol": "tcp"}]
    trend = traffic_trend(packets, bucket_seconds=10)
    assert len(trend) == 2
    assert trend[0]["packets"] == 1
