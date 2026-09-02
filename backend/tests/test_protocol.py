from pathlib import Path

import pytest

from app.services.protocol_service import protocol_distribution, protocol_tree
from app.services.protocol_service import parse_pcap


def test_protocol_tree() -> None:
    tree = protocol_tree({"tcp": 10, "http": 5})
    assert tree == [{"name": "tcp", "count": 10}, {"name": "http", "count": 5}]


def test_protocol_distribution_missing_file(tmp_path: Path) -> None:
    if not pytest.importorskip("shutil").which("tshark"):
        pytest.skip("tshark unavailable")
    result = protocol_distribution(tmp_path / "missing.pcap")
    assert result == {}


def test_parse_fixture_pcap() -> None:
    fixture = Path(__file__).parent / "fixtures" / "sample.pcap"
    if not fixture.exists():
        pytest.skip("fixture not generated")
    result = parse_pcap(fixture, max_packets=100)
    assert result["packet_count"] >= 20
    assert result["flows"]
