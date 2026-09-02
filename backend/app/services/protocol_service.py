import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "frame.protocols",
    "_ws.col.Protocol",
    "_ws.col.Info",
]


def run_tshark(args: list[str], timeout: int = 300) -> tuple[str, str, int]:
    result = subprocess.run(["tshark", *args], capture_output=True, text=True, timeout=timeout)
    return result.stdout, result.stderr, result.returncode


def protocol_distribution(path: Path, timeout: int = 300) -> dict[str, int]:
    stdout, stderr, code = run_tshark(["-r", str(path), "-T", "fields", "-e", "frame.protocols"], timeout)
    if code != 0:
        return {}
    counter: Counter[str] = Counter()
    for line in stdout.splitlines():
        for proto in line.split(":"):
            if proto:
                counter[proto] += 1
    return dict(counter.most_common(50))


def extract_app_fields(path: Path, max_rows: int = 5000, timeout: int = 300) -> list[dict[str, Any]]:
    fields = ["http.request.method", "http.host", "http.response.code", "dns.qry.name", "dns.flags.response", "tls.handshake.type"]
    field_args = [item for field in fields for item in ("-e", field)]
    stdout, _, code = run_tshark(["-r", str(path), "-T", "fields", *field_args, "-c", str(max_rows)], timeout)
    if code != 0:
        return []
    rows = []
    for line in stdout.splitlines()[:max_rows]:
        parts = line.split("\t")
        rows.append({
            "http_method": parts[0] if len(parts) > 0 else "",
            "http_host": parts[1] if len(parts) > 1 else "",
            "http_status": parts[2] if len(parts) > 2 else "",
            "dns_query": parts[3] if len(parts) > 3 else "",
            "dns_response": parts[4] if len(parts) > 4 else "",
            "tls_handshake_type": parts[5] if len(parts) > 5 else "",
        })
    return rows


def _dpkt_parse(path: Path, max_packets: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    try:
        import dpkt
    except ImportError as exc:
        raise RuntimeError("tshark 不可用且未安装 dpkt") from exc
    flows: dict[tuple[Any, ...], dict[str, Any]] = {}
    packets = []
    with path.open("rb") as handle:
        try:
            pcap = dpkt.pcap.Reader(handle)
        except Exception:
            handle.seek(0)
            pcap = dpkt.pcapng.Reader(handle)
        for index, (timestamp, raw) in enumerate(pcap, start=1):
            if index > max_packets:
                break
            eth = dpkt.ethernet.Ethernet(raw)
            ip = eth.data if isinstance(eth.data, dpkt.ip.IP) else None
            if not ip:
                continue
            src, dst = ip.src, ip.dst
            src_port = dst_port = 0
            proto = "other"
            payload = ip.data
            if isinstance(payload, dpkt.tcp.TCP):
                proto = "tcp"
                src_port, dst_port = payload.sport, payload.dport
            elif isinstance(payload, dpkt.udp.UDP):
                proto = "udp"
                src_port, dst_port = payload.sport, payload.dport
            packets.append({"number": index, "timestamp": timestamp, "src_ip": src, "dst_ip": dst, "src_port": src_port, "dst_port": dst_port, "protocol": proto, "length": len(raw), "info": ""})
            key = (src, src_port, dst, dst_port, proto)
            flow = flows.setdefault(key, {"src_ip": src, "src_port": src_port, "dst_ip": dst, "dst_port": dst_port, "protocol": proto, "packets": 0, "bytes": 0, "start_time": timestamp, "end_time": timestamp})
            flow["packets"] += 1
            flow["bytes"] += len(raw)
            flow["end_time"] = timestamp
    return packets, list(flows.values()), len(packets)


def parse_pcap(path: Path, max_packets: int = 5000) -> dict[str, Any]:
    protocol_summary = protocol_distribution(path)
    app_fields = extract_app_fields(path, max_rows=min(max_packets, 5000))
    packets: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    packet_count = 0
    use_dpkt = False
    field_args = [item for field in TSHARK_FIELDS for item in ("-e", field)]
    stdout, stderr, code = run_tshark(["-r", str(path), "-T", "fields", *field_args, "-c", str(max_packets)], timeout=300)
    if code == 0:
        flow_map: dict[tuple[str, int, str, int, str], dict[str, Any]] = {}
        for line in stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 12:
                continue
            number = int(parts[0] or 0)
            try:
                timestamp = float(parts[1] or 0)
            except ValueError:
                timestamp = 0.0
            src_ip, dst_ip = parts[2], parts[3]
            src_port = int(parts[4] or 0) if parts[4] else 0
            dst_port = int(parts[5] or 0) if parts[5] else 0
            src_port = int(parts[6] or 0) if src_port == 0 and parts[6] else src_port
            dst_port = int(parts[7] or 0) if dst_port == 0 and parts[7] else dst_port
            protocol = parts[10] or "other"
            length = int(parts[8] or 0)
            info = parts[11] or ""
            packets.append({"number": number, "timestamp": timestamp, "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port, "protocol": protocol, "length": length, "info": info})
            key = (src_ip, src_port, dst_ip, dst_port, protocol)
            flow = flow_map.setdefault(key, {"src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol, "packets": 0, "bytes": 0, "start_time": timestamp, "end_time": timestamp})
            flow["packets"] += 1
            flow["bytes"] += length
            flow["end_time"] = timestamp
            packet_count = number
        flows = list(flow_map.values())
    else:
        packets, flows, packet_count = _dpkt_parse(path, max_packets)
        use_dpkt = True
    return {
        "packet_count": packet_count,
        "packets": packets,
        "flows": flows,
        "protocol_summary": protocol_summary,
        "app_fields": app_fields,
        "engine": "tshark" if not use_dpkt else "dpkt",
    }


def flow_timeline(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not flows:
        return []
    return sorted(flows, key=lambda item: item.get("start_time", 0))


def protocol_tree(summary: dict[str, int]) -> list[dict[str, Any]]:
    return [{"name": name, "count": count} for name, count in summary.items()]
