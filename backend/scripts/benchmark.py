#!/usr/bin/env python3
"""Benchmark normal, scan, C2, data leak and sensitive samples."""

import csv
import io
import socket
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dpkt

from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.risk_engine.engine import RiskEngine
from app.services.protocol_service import parse_pcap


def write_pcap(path: Path, ports: list[int], interval: float, dst_ips: list[str] | None = None) -> None:
    dst_ips = dst_ips or ["10.0.0.2"]
    with path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        eth = dpkt.ethernet.Ethernet(src=b"\x00\x11\x22\x33\x44\x55", dst=b"\x66\x77\x88\x99\xaa\xbb")
        ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton(dst_ips[0]), ttl=64)
        ip.v = 4
        ip.hl = 5
        ip.p = socket.IPPROTO_TCP
        ip.sum = 0
        for idx, port in enumerate(ports):
            dst = dst_ips[idx % len(dst_ips)]
            ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton(dst), ttl=64)
            ip.v = 4
            ip.hl = 5
            ip.p = socket.IPPROTO_TCP
            ip.sum = 0
            tcp = dpkt.tcp.TCP(sport=44444, dport=port, flags=dpkt.tcp.TH_SYN, seq=100 + idx)
            ip.data = tcp
            ip.len = ip.data.__len__() + 20
            eth.data = ip
            writer.writepkt(eth, ts=1700000300.0 + idx * interval)


def main() -> None:
    pipeline = DetectionPipeline(registry, RiskEngine())
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        cases = {
            "normal": write_pcap(tmp_path / "normal.pcap", [443], 0.1),
            "scan": write_pcap(tmp_path / "scan.pcap", list(range(1, 31)), 0.001),
            "c2": write_pcap(tmp_path / "c2.pcap", [8080] * 20, 0.1),
        }
        for name, _ in cases.items():
            pcap = tmp_path / f"{name}.pcap"
            parsed = parse_pcap(pcap)
            context = DetectionContext(target_type="pcap", target_id=name, path=pcap, flows=parsed["flows"], packets=parsed["packets"])
            started = time.perf_counter()
            result = pipeline.run(context)
            elapsed = time.perf_counter() - started
            print({"case": name, "findings": len(result.findings), "risk": result.risk_level, "score": result.risk_score, "elapsed": round(elapsed, 3)})
        sensitive = tmp_path / "sensitive.csv"
        sensitive.write_text("phone,email\n13800138000,test@example.com\n", encoding="utf-8")
        context = DetectionContext(target_type="file", files=[sensitive])
        result = pipeline.run(context)
        print({"case": "sensitive_file", "findings": len(result.findings), "risk": result.risk_level, "score": result.risk_score})


if __name__ == "__main__":
    main()
