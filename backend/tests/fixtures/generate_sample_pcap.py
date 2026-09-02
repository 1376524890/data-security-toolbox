#!/usr/bin/env python3
"""Generate a small real PCAP fixture for protocol tests."""

import dpkt
import socket
from pathlib import Path


def main() -> Path:
    output = Path(__file__).parent / "sample.pcap"
    with output.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        eth = dpkt.ethernet.Ethernet(src=b"\x00\x11\x22\x33\x44\x55", dst=b"\x66\x77\x88\x99\xaa\xbb")
        ip = dpkt.ip.IP(src=socket.inet_aton("10.0.0.1"), dst=socket.inet_aton("10.0.0.2"), ttl=64)
        ip.v = 4
        ip.hl = 5
        ip.p = socket.IPPROTO_TCP
        ip.sum = 0
        tcp = dpkt.tcp.TCP(sport=12345, dport=5432, flags=dpkt.tcp.TH_SYN, seq=100)
        ip.data = tcp
        ip.len = ip.data.__len__() + 20
        eth.data = ip
        for index in range(20):
            writer.writepkt(eth, ts=1700000000.0 + index * 0.01)
    return output


if __name__ == "__main__":
    print(main())
