"""Generate synthetic captures and verify passive DLP behavior."""
import json
import socket
from pathlib import Path

import dpkt
from app.services.dlp_service import DEFAULT_POLICY, analyze_capture

out = Path('/app/data/storage/dlp-verification')
out.mkdir(parents=True, exist_ok=True)
cases = {
    'phone': (b'phone=13800138000', {'phone'}),
    'email': (b'email=synthetic@example.test', {'email'}),
    'clean': (b'hello synthetic test', set()),
    'tls': (b'\x16\x03\x03\x00\x20encrypted synthetic bytes', set()),
}
results = []
for name, (body, expected) in cases.items():
    payload = body if name == 'tls' else b'POST /test HTTP/1.1\r\nHost: example.test\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
    tcp = dpkt.tcp.TCP(sport=50000, dport=443 if name == 'tls' else 80, seq=1, flags=dpkt.tcp.TH_ACK, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton('192.0.2.1'), dst=socket.inet_aton('192.0.2.2'), p=6, data=tcp)
    ip.len = len(ip)
    frame = dpkt.ethernet.Ethernet(src=b'\x01'*6, dst=b'\x02'*6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    path = out / (name + '.pcap')
    with path.open('wb') as stream:
        writer = dpkt.pcap.Writer(stream)
        writer.writepkt(bytes(frame), ts=1)
    report, _, findings = analyze_capture(path, DEFAULT_POLICY)
    actual = {hit['kind'] for finding in findings for hit in finding['evidence']['matches']}
    assert actual == expected, (name, actual)
    if name == 'tls':
        assert report['coverage']['encrypted_streams'] == 1
    results.append({'case': name, 'matches': sorted(actual), 'coverage': report['coverage'], 'passed': True})
print(json.dumps(results))
