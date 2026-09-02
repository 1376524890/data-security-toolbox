import socket
from pathlib import Path

import dpkt

from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.risk_engine.engine import RiskEngine
from app.services.protocol_service import parse_pcap


def _write_scan_pcap(path: Path) -> None:
    with path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        eth = dpkt.ethernet.Ethernet(src=b"\x00\x11\x22\x33\x44\x55", dst=b"\x66\x77\x88\x99\xaa\xbb")
        ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton("10.0.0.2"), ttl=64)
        ip.v = 4
        ip.hl = 5
        ip.p = socket.IPPROTO_TCP
        ip.sum = 0
        for idx, port in enumerate(range(1, 31)):
            tcp = dpkt.tcp.TCP(sport=44444, dport=port, flags=dpkt.tcp.TH_SYN, seq=100 + idx)
            ip.data = tcp
            ip.len = ip.data.__len__() + 20
            eth.data = ip
            writer.writepkt(eth, ts=1700000200.0 + idx * 0.001)


def test_pcap_to_risk_pipeline(tmp_path: Path) -> None:
    pcap = tmp_path / "scan.pcap"
    _write_scan_pcap(pcap)
    parsed = parse_pcap(pcap)
    context = DetectionContext(target_type="pcap", target_id="scan", path=pcap, flows=parsed["flows"], packets=parsed["packets"], data={"protocol_summary": parsed["protocol_summary"]})
    result = DetectionPipeline(registry, RiskEngine()).run(context)
    rules = {item.rule_id for item in result.findings}
    assert "NET_SCAN_001" in rules or "port_scan" in rules
    assert result.risk_score > 0
    assert result.risk_level in {"Critical", "High", "Medium", "Low"}

