from __future__ import annotations

import shutil
import subprocess
import threading
import time
from collections import Counter
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


class AnalysisTimeout(Exception):
    """Raised when a tshark subprocess exceeds its configured timeout."""


class _WatchdogState:
    def __init__(self) -> None:
        self.timed_out = False


def _kill_process(process: subprocess.Popen, state: _WatchdogState) -> None:
    state.timed_out = True
    try:
        process.terminate()
    except Exception:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except Exception:
            pass


def stream_tshark(args: list[str], timeout: int = 300):
    """Yield decoded lines from tshark without buffering the full output.

    A watchdog thread enforces the timeout even when tshark produces no output
    (e.g. a hung reader on a huge pcap), terminating the process after a grace
    period and then raising :class:`AnalysisTimeout`.
    """
    if not shutil.which("tshark"):
        return
    process = subprocess.Popen(
        ["tshark", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    state = _WatchdogState()
    watchdog: threading.Timer | None = None
    if timeout and timeout > 0:
        watchdog = threading.Timer(timeout, _kill_process, args=(process, state))
        watchdog.daemon = True
        watchdog.start()
    try:
        if process.stdout is None:
            return
        for line in process.stdout:
            yield line.rstrip("\n")
        if state.timed_out:
            raise AnalysisTimeout(f"tshark exceeded {timeout}s timeout")
    finally:
        if watchdog:
            watchdog.cancel()
        try:
            process.stdout.close()
        except Exception:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def capinfos(path: Path, timeout: int = 30) -> dict[str, Any]:
    binary = shutil.which("capinfos")
    if not binary:
        return {}
    try:
        result = subprocess.run(
            [binary, "-T", "-t", "-c", "-u", "-a", "-e", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return {}
    if result.returncode != 0:
        return {}
    lines = result.stdout.splitlines()
    if len(lines) < 2:
        return {}
    headers = lines[0].split("\t")
    values = lines[1].split("\t")
    data = dict(zip(headers, values))

    def _number(value: Any) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    return {
        "file_type": data.get("File type", ""),
        "total_packets": int(_number(data.get("Number of packets"))),
        "duration": _number(data.get("Capture duration (seconds)")),
        "capture_start": data.get("Start time", ""),
        "capture_end": data.get("End time", ""),
    }


def protocol_distribution(path: Path, timeout: int = 300) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for line in stream_tshark(["-r", str(path), "-T", "fields", "-e", "frame.protocols"], timeout):
        for proto in line.split(":"):
            if proto:
                counter[proto] += 1
    return dict(counter.most_common(50))


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


def parse_pcap(path: Path, max_index_packets: int = 10000, max_packets: int | None = None, timeout: int = 300) -> dict[str, Any]:
    """Parse a pcap in a single main tshark pass.

    One pass builds the packet UI index, flow aggregation, protocol
    distribution and basic application metadata, avoiding the previous
    multi-pass (protocol_distribution + extract_app_fields + fields) behaviour.
    """
    if max_packets is not None:
        max_index_packets = max_packets
    info = capinfos(path)
    packets: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    total_packet_count = int(info.get("total_packets") or 0)
    indexed_packet_count = 0
    flow_map: dict[tuple[str, int, str, int, str], dict[str, Any]] = {}
    protocol_counter: Counter[str] = Counter()
    field_args = [item for field in TSHARK_FIELDS for item in ("-e", field)]
    seen_packets = 0
    for line in stream_tshark(["-r", str(path), "-T", "fields", *field_args], timeout=timeout):
        seen_packets += 1
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
        info_text = parts[11] or ""
        for proto in parts[9].split(":"):
            if proto:
                protocol_counter[proto] += 1
        if indexed_packet_count < max_index_packets:
            packets.append({"number": number, "timestamp": timestamp, "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port, "protocol": protocol, "length": length, "info": info_text})
            indexed_packet_count += 1
        key = (src_ip, src_port, dst_ip, dst_port, protocol)
        flow = flow_map.setdefault(key, {"src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol, "packets": 0, "bytes": 0, "start_time": timestamp, "end_time": timestamp})
        flow["packets"] += 1
        flow["bytes"] += length
        flow["end_time"] = timestamp
    flows = list(flow_map.values())
    protocol_summary = dict(protocol_counter.most_common(50))
    if seen_packets and not total_packet_count:
        total_packet_count = seen_packets
    if not packets:
        packets, fallback_flows, fallback_count = _dpkt_parse(path, max_index_packets)
        if fallback_count:
            total_packet_count = fallback_count
            indexed_packet_count = len(packets)
            flows = fallback_flows or flows
            if not protocol_summary:
                protocol_summary = dict(Counter(flow["protocol"] for flow in flows))
    return {
        "packet_count": total_packet_count,
        "total_packet_count": total_packet_count,
        "indexed_packet_count": indexed_packet_count,
        "packets": packets,
        "flows": flows,
        "protocol_summary": protocol_summary,
        "app_fields": [],
        "file_type": info.get("file_type", ""),
        "capture_start": info.get("capture_start", ""),
        "capture_end": info.get("capture_end", ""),
        "duration": float(info.get("duration") or 0),
        "engine": "tshark" if seen_packets else "dpkt",
    }


def flow_timeline(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not flows:
        return []
    return sorted(flows, key=lambda item: item.get("start_time", 0))


def protocol_tree(summary: dict[str, int]) -> list[dict[str, Any]]:
    return [{"name": name, "count": count} for name, count in summary.items()]
