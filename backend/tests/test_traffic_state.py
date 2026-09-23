from __future__ import annotations

from app.core.config import settings
from app.engine.core.context import DetectionContext
from app.engine.traffic_engine.engine import TrafficEngine
from app.services.traffic_state import rolling_traffic_state

PROBE = "test-probe"


def _segment(ports: range, now: float) -> list[dict]:
    return [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": port, "src_port": 12345, "protocol": "tcp", "packets": 1, "bytes": 60} for port in ports]


def _reply(src: str, dst: str, service: int, client_port: int, now: float) -> dict:
    """One server reply: the ephemeral port is the *destination* here."""
    return {
        "src_ip": src, "dst_ip": dst, "src_port": service, "dst_port": client_port,
        "protocol": "udp", "packets": 1, "bytes": 80,
    }


def test_cross_segment_accumulates_unique_ports() -> None:
    rolling_traffic_state.reset()
    base = 1_700_000_000.0
    rolling_traffic_state.observe(PROBE, _segment(range(1, 11), base), now=base)
    rolling_traffic_state.observe(PROBE, _segment(range(11, 21), base), now=base + 5)
    rolling_traffic_state.observe(PROBE, _segment(range(21, 26), base), now=base + 10)
    snap = rolling_traffic_state.snapshot(
        PROBE, "10.0.0.1", "10.0.0.2", window_seconds=60, now=base + 10
    )
    assert len(snap["dst_ports"]) >= 20
    assert snap["dst_ports"] == list(range(1, 26))


def test_strict_window_expiration_prunes_old_ports() -> None:
    rolling_traffic_state.reset()
    base = 1_700_000_000.0
    rolling_traffic_state.observe(PROBE, _segment(range(1, 11), base), now=base)
    # 30s later, all original ports are still within the 60s window.
    snap_in = rolling_traffic_state.snapshot(
        PROBE, "10.0.0.1", "10.0.0.2", window_seconds=60, now=base + 30
    )
    assert len(snap_in["dst_ports"]) == 10
    # 70s later, everything has expired out of the strict 60s window.
    snap_out = rolling_traffic_state.snapshot(
        PROBE, "10.0.0.1", "10.0.0.2", window_seconds=60, now=base + 70
    )
    assert snap_out["dst_ports"] == []


def test_a_servers_replies_are_not_a_scan_of_its_clients() -> None:
    """The source of the false positive this metric used to produce.

    A DNS resolver answers many clients; every reply is its own conversation
    (`114.114.114.114:53 -> client:ephemeral`) with a different destination port.
    Counting distinct destination ports per *source address* therefore described
    the resolver as scanning the network it serves, on every busy capture.
    """
    rolling_traffic_state.reset()
    base = 1_700_000_000.0
    replies = [
        _reply("114.114.114.114", f"10.0.0.{index}", 53, 33000 + index, base)
        for index in range(1, 41)
    ]
    rolling_traffic_state.observe(PROBE, replies, now=base)
    for index in range(1, 41):
        snap = rolling_traffic_state.snapshot(
            PROBE, "114.114.114.114", f"10.0.0.{index}", window_seconds=60, now=base
        )
        # One conversation, one service port: never a scan.
        assert snap["dst_ports"] == [53]

    context = DetectionContext(
        target_type="pcap", flows=replies, packets=[], data={"probe_id": PROBE}
    )
    findings = TrafficEngine().analyze(context)
    assert [item for item in findings if item.rule_id == "NETWORK_PORT_SCAN"] == []


def test_one_source_many_clients_on_one_port_is_not_a_scan() -> None:
    """A client opening 30 sockets is one port on one server, not 30 ports."""
    rolling_traffic_state.reset()
    base = 1_700_000_000.0
    flows = [
        {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 40000 + index,
            "dst_port": 443, "protocol": "tcp", "packets": 1, "bytes": 60,
        }
        for index in range(30)
    ]
    rolling_traffic_state.observe(PROBE, flows, now=base)
    snap = rolling_traffic_state.snapshot(PROBE, "10.0.0.1", "10.0.0.2", 60, now=base)
    assert snap["dst_ports"] == [443]


def test_single_segment_below_threshold_does_not_fire_rolling() -> None:
    rolling_traffic_state.reset()
    settings.port_scan_ports_threshold = 20
    settings.port_scan_window_seconds = 60
    flows = _segment(range(1, 11), 1_700_000_000.0)  # 10 ports < 20
    context = DetectionContext(target_type="pcap", flows=flows, packets=[], data={"probe_id": PROBE})
    findings = TrafficEngine().analyze(context)
    rolling = [item for item in findings if item.rule_id == "NETWORK_PORT_SCAN" and item.evidence.get("rolling")]
    assert rolling == []


def test_cross_segment_engine_fires_once() -> None:
    rolling_traffic_state.reset()
    settings.port_scan_ports_threshold = 20
    settings.port_scan_window_seconds = 60
    base = 1_700_000_000.0
    rolling_findings = []
    # Each single segment is below the threshold; only the cross-segment
    # accumulation crosses it. The window cooldown must yield exactly one
    # rolling finding for the whole window.
    for ports, delta in [(range(1, 11), 0), (range(11, 21), 5), (range(21, 26), 10)]:
        context = DetectionContext(target_type="pcap", flows=_segment(ports, base + delta), packets=[], data={"probe_id": PROBE})
        findings = TrafficEngine().analyze(context)
        rolling_findings.extend(item for item in findings if item.rule_id == "NETWORK_PORT_SCAN" and item.evidence.get("rolling"))
    assert len(rolling_findings) == 1
    assert rolling_findings[0].evidence["port_count"] >= 20
    assert rolling_findings[0].evidence["rolling"] is True


def test_seen_cooldown_window() -> None:
    rolling_traffic_state.reset()
    base = 1_700_000_000.0
    assert rolling_traffic_state.seen(PROBE, "10.0.0.1", "NETWORK_PORT_SCAN", 60) is False
    assert rolling_traffic_state.seen(PROBE, "10.0.0.1", "NETWORK_PORT_SCAN", 60) is True
    # A fresh source with a short cooldown fires immediately and then is
    # suppressed for its own window.
    assert rolling_traffic_state.seen(PROBE, "10.0.0.5", "NETWORK_PORT_SCAN", 1) is False
    assert rolling_traffic_state.seen(PROBE, "10.0.0.5", "NETWORK_PORT_SCAN", 1) is True
