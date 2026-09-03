import socket
from pathlib import Path

import dpkt


def write_scan_pcap(path: Path, src: str = "10.0.0.25", dst: str = "10.0.0.2", ports: int = 30) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        eth = dpkt.ethernet.Ethernet(src=b"\x00\x11\x22\x33\x44\x55", dst=b"\x66\x77\x88\x99\xaa\xbb")
        for index in range(ports):
            ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), ttl=64)
            ip.v = 4
            ip.hl = 5
            ip.p = socket.IPPROTO_TCP
            ip.sum = 0
            tcp = dpkt.tcp.TCP(sport=12345, dport=1 + index, flags=dpkt.tcp.TH_SYN, seq=100 + index)
            ip.data = tcp
            ip.len = ip.data.__len__() + 20
            eth.data = ip
            writer.writepkt(eth, ts=1700000000.0 + index * 0.01)
    return path
