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
