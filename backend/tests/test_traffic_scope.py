"""Scope and direction rules that keep traffic anomaly findings meaningful.

These pin the platform's single largest false-positive source. A capture is
*directional*, so a DNS server's answers arrive as one flow per client
(``114.114.114.114:53 -> client:33209``); counting distinct destination ports
per source address therefore described every busy server as a port scanner, and
counting them for the platform's own loopback and container bridge described the
platform as one too. 179 ``NETWORK_PORT_SCAN`` and 485 ``NET_BROAD_001``
findings against one host were traced to exactly this.
"""
from app.services.traffic_scope import (
    address_ignored,
    filter_flows,
    filter_packets,
    is_ignored,
    service_port,
)
from app.services.traffic_service import detect_anomalies


def test_service_port_is_the_service_end_not_the_ephemeral_one() -> None:
    # The reply has the ports swapped, so the pair must agree on which end is
    # the service: both orderings give 53, not 53 and 33209.
    assert service_port(33209, 53) == 53
    assert service_port(53, 33209) == 53
    # Only one end known: that end is all there is to go on.
    assert service_port(None, 80) == 80
    assert service_port(443, None) == 443
    # Both ends in the registered range: the smaller one is the best guess.
    assert service_port(50000, 60000) == 50000


def test_scope_drops_loopback_link_local_multicast_and_unspecified() -> None:
    assert address_ignored("127.0.0.1")
    assert address_ignored("169.254.10.10")
    assert address_ignored("224.0.0.251")
    assert address_ignored("0.0.0.0")
    assert address_ignored("::1")
    assert address_ignored("fe80::1")
    assert not address_ignored("10.0.0.9")


def test_filtering_reports_how_much_it_dropped() -> None:
    flows = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1234, "dst_port": 445},
        {"src_ip": "127.0.0.1", "dst_ip": "10.0.0.2", "src_port": 1, "dst_port": 2},
    ]
    kept, dropped = filter_flows(flows)
    assert [flow["src_ip"] for flow in kept] == ["10.0.0.1"]
    assert dropped == 1
    kept_packets, dropped_packets = filter_packets(
        [{"src_ip": "224.0.0.1"}, {"src_ip": "10.0.0.1"}]
    )
    assert [packet["src_ip"] for packet in kept_packets] == ["10.0.0.1"]
    assert dropped_packets == 1


def test_a_busy_dns_server_is_not_a_port_scanner() -> None:
    """One service port, many clients: the shape that used to be a scan."""
    flows = [
        {"src_ip": "114.114.114.114", "dst_ip": "192.168.110.168", "src_port": 53,
         "dst_port": 30000 + index, "protocol": "udp", "bytes": 100, "packets": 1}
        for index in range(30)
    ]
    assert not any(item["rule"] == "NETWORK_PORT_SCAN" for item in detect_anomalies(flows, []))


def test_many_ports_on_one_target_is_still_reported() -> None:
    flows = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000 + port,
         "dst_port": port, "protocol": "tcp", "bytes": 60, "packets": 1}
        for port in range(20, 45)
    ]
    anomalies = detect_anomalies(flows, [])
    scan = next(item for item in anomalies if item["rule"] == "NETWORK_PORT_SCAN")
    # The evidence has to name the target, or an operator cannot tell a real
    # scanner from a server answering its clients.
    assert scan["evidence"]["dst"] == "10.0.0.2"
    assert scan["evidence"]["port_count"] == 25


def test_loopback_scan_shaped_traffic_reaches_no_rule() -> None:
    flows = [
        {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "src_port": 40000 + port,
         "dst_port": port, "protocol": "tcp", "bytes": 60, "packets": 1}
        for port in range(20, 45)
    ]
    assert detect_anomalies(flows, []) == []
    assert is_ignored(flows[0])


def test_a_container_bridge_is_only_ignored_when_the_operator_names_it() -> None:
    """172.16/12 is a legitimate private range, so it cannot be dropped by
    default; the platform's own bridge has to be configured. This pins that the
    default is *not* silently broad - a fix that ignored every private address
    would hide the customer's own network."""
    flows = [
        {"src_ip": "172.23.0.7", "dst_ip": "172.23.0.2", "src_port": 40000 + port,
         "dst_port": port, "protocol": "tcp", "bytes": 60, "packets": 1}
        for port in range(20, 45)
    ]
    assert not address_ignored("172.23.0.2")
    assert any(item["rule"] == "NETWORK_PORT_SCAN" for item in detect_anomalies(flows, []))
