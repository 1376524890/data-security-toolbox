from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from app.services.protocol_service import AnalysisTimeout, parse_pcap, stream_tshark
from tests.fixtures.generate_scan_pcap import write_scan_pcap


def test_stream_tshark_watchdog_timeout(tmp_path: Path, monkeypatch) -> None:
    fake = tmp_path / "tshark"
    fake.write_text("#!/bin/sh\nfor i in $(seq 1 10000); do echo 'line'; sleep 0.2; done\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    start = time.monotonic()
    with pytest.raises(AnalysisTimeout):
        for _ in stream_tshark(["-r", "x.pcap"], timeout=1):
            pass
    assert time.monotonic() - start < 8


def test_parse_pcap_total_exceeds_index_limit(tmp_path: Path) -> None:
    pcap = write_scan_pcap(tmp_path / "big.pcap", ports=200)
    result = parse_pcap(pcap, max_index_packets=50)
    assert result["total_packet_count"] > result["indexed_packet_count"]
    assert len(result["packets"]) == 50
    assert result["engine"] in {"tshark", "dpkt"}


def test_parse_pcap_single_pass_protocol_summary(tmp_path: Path) -> None:
    pcap = write_scan_pcap(tmp_path / "scan.pcap", ports=30)
    result = parse_pcap(pcap)
    assert result["packet_count"] >= 30
    assert result["protocol_summary"]
    assert any(name in result["protocol_summary"] for name in ("tcp", "ip", "eth"))


def test_metadata_passes_disable_tcp_reassembly(tmp_path: Path, monkeypatch) -> None:
    """The passes that gate analysis must not pay for TCP reassembly.

    Reassembly is quadratic in the length of a single stream: a saturated 64 MB
    segment took >600s with it on and ~1s with it off, which is how one capture
    segment came to burn the whole 300s analysis budget. The flag is asserted
    here because dropping it is silent - the pass still returns plausible data,
    just far too slowly to keep up with capture.
    """
    from app.services import protocol_service

    seen: list[list[str]] = []
    # One well-formed row, so ``parse_pcap`` indexes a packet and never falls
    # back to the dpkt reader (which would touch a real file on disk).
    row = "\t".join(
        ["1", "1234.25", "10.0.0.1", "10.0.0.2", "1234", "80", "", "", "100",
         "eth:ip:tcp", "TCP", "payload", "", "", "", ""]
    )

    def fake_stream(args, timeout=300):
        seen.append(list(args))
        return iter([row])

    monkeypatch.setattr(protocol_service, "capinfos", lambda _: {})
    monkeypatch.setattr(protocol_service, "stream_tshark", fake_stream)

    protocol_service.protocol_distribution(tmp_path / "x.pcap")
    parse_pcap(tmp_path / "x.pcap")
    assert len(seen) == 2
    for args in seen:
        assert "tcp.desegment_tcp_streams:FALSE" in args


def test_tcp_stream_inventory_disables_tcp_reassembly(tmp_path: Path, monkeypatch) -> None:
    """The stream inventory reads ``tcp.len``/``tcp.payload`` per frame, so it
    has the same exposure to a long stream as the metadata passes above."""
    from app.engine.protocol_engine import engine as protocol_engine

    seen: list[list[str]] = []
    monkeypatch.setattr(
        protocol_engine, "stream_tshark",
        lambda args, timeout=300: (seen.append(list(args)), iter([]))[1],
    )
    protocol_engine.tcp_streams(tmp_path / "x.pcap")
    assert len(seen) == 1
    assert "tcp.desegment_tcp_streams:FALSE" in seen[0]
