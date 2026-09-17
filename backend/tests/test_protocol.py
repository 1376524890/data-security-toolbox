from pathlib import Path

import pytest

from app.services.protocol_service import protocol_distribution, protocol_layer, protocol_tree
from app.services.protocol_service import parse_pcap


def test_protocol_tree() -> None:
    tree = protocol_tree({"tcp": 10, "http": 5})
    # Counted most-used first, and annotated with the layer so the console can
    # chart application protocols instead of frame plumbing.
    assert tree == [
        {"name": "tcp", "count": 10, "layer": "transport"},
        {"name": "http", "count": 5, "layer": "application"},
    ]


def test_protocol_layer_separates_plumbing_from_application_protocols() -> None:
    # frame.protocols lists every layer of a frame; a distribution topped by
    # "sll" and "ethertype" tells an operator nothing.
    assert protocol_layer("sll") == "link"
    assert protocol_layer("ethertype") == "link"
    assert protocol_layer("vlan") == "link"
    assert protocol_layer("ip") == "network"
    assert protocol_layer("icmpv6") == "network"
    assert protocol_layer("tcp") == "transport"
    assert protocol_layer("UDP") == "transport"
    assert protocol_layer("http") == "application"
    # tshark labels some frames with a family or version suffix.
    assert protocol_layer("HTTP/JSON") == "application"
    assert protocol_layer("SSHv2") == "application"
    assert protocol_layer("TLSv1.2") == "application"


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


def test_first_num_handles_comma_lists() -> None:
    from app.engine.protocol_engine.engine import _first_num
    assert _first_num("16,16,16", int, 0) == 16
    assert _first_num("", int, 0) == 0
    assert _first_num("abc", int, 0) == 0
    assert _first_num("3.14,2.0", float, 0.0) == 3.14
