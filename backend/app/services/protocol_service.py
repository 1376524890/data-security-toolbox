from __future__ import annotations

import shutil
import subprocess
import json
import re
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


# ---------------------------------------------------------------------------
# Packet detail (raw bytes + protocol tree) via tshark -T json -x
# ---------------------------------------------------------------------------

_LAYER_PRETTY = {
    "eth": "Ethernet II",
    "ethertype": "Ethertype",
    "ip": "Internet Protocol Version 4",
    "ipv6": "Internet Protocol Version 6",
    "arp": "Address Resolution Protocol",
    "icmp": "ICMP",
    "icmpv6": "ICMPv6",
    "tcp": "TCP",
    "udp": "UDP",
    "http": "HTTP",
    "dns": "DNS",
    "tls": "TLS",
    "ssl": "SSL",
    "data": "Data",
    "frame": "Frame",
}


def _pretty_layer(key: str) -> str:
    return _LAYER_PRETTY.get(key, key.replace("_", " ").title())


def _flatten_fields(prefix: str, fields: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for field, value in fields.items():
        if field.endswith("_raw") or field.endswith("_tree"):
            continue
        if isinstance(value, dict):
            continue
        label = field[len(prefix) + 1 :] if field.startswith(prefix + ".") else field
        if isinstance(value, list):
            strings = [item for item in value if isinstance(item, str)]
            if not strings:
                continue
            value = strings[0]
        if value is None:
            continue
        items.append({"label": label, "value": str(value)})
    return items


def _build_layers(layers: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key, value in layers.items():
        if key.endswith("_raw") or not isinstance(value, dict):
            continue
        items = _flatten_fields(key, value)
        if items:
            result.append({"name": _pretty_layer(key), "items": items})
    return result


def packet_detail(path: Path, number: int, timeout: int = 60) -> dict[str, Any] | None:
    """Return ``{raw, layers}`` for a single frame using tshark ``-T json -x``.

    ``raw`` is the full frame hex string and ``layers`` is an ordered protocol
    tree of ``{name, items: [{label, value}]}``. Returns ``None`` when tshark is
    unavailable, the frame does not exist, or the pcap is unreadable.
    """
    if not shutil.which("tshark"):
        return None
    args = ["-r", str(path), "-Y", f"frame.number=={int(number)}", "-T", "json", "-x"]
    try:
        proc = subprocess.run(["tshark", *args], capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        data = json.loads(proc.stdout)
    except Exception:
        return None
    if not isinstance(data, list) or not data:
        return None
    source = data[0].get("_source", {})
    layers = source.get("layers", {})
    if not isinstance(layers, dict):
        return None
    raw = ""
    frame_raw = layers.get("frame_raw")
    if isinstance(frame_raw, list) and frame_raw and isinstance(frame_raw[0], str):
        raw = frame_raw[0]
    return {"raw": raw, "layers": _build_layers(layers)}


def _parse_follow_ascii(text: str) -> dict[str, Any]:
    """Parse tshark ``follow,tcp,ascii`` output into directional stream chunks."""
    nodes: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = re.match(r"^Node\s+(\d+):\s+([\d.]+):(\d+)", line)
        if match:
            idx = int(match.group(1))
            nodes.append({"node": idx, "ip": match.group(2), "port": int(match.group(3))})
    # Data blocks are: <byte_count>\\n<ascii payload>\\n\\n
    chunks: list[dict[str, Any]] = []
    lines = text.splitlines()
    i = 0
    current_node = None
    # Determine current direction from the packet header lines that precede a block
    # is unreliable; instead we re-run hex follow to map direction. For ASCII we
    # keep the raw blocks and let the frontend render them sequentially.
    while i < len(lines):
        line = lines[i]
        if line and line.isdigit():
            count = int(line)
            payload_lines: list[str] = []
            j = i + 1
            while j < len(lines) and lines[j] != "":
                payload_lines.append(lines[j])
                j += 1
            chunks.append({"bytes": count, "ascii": "\n".join(payload_lines)})
            i = j + 1
            continue
        i += 1
    return {"nodes": nodes, "chunks": chunks}


def _parse_follow_hex(text: str) -> list[str]:
    """Parse tshark ``follow,tcp,hex`` output into per-chunk hex strings."""
    chunks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.startswith("\t"):
            if current:
                chunks.append("".join(current))
            current = []
            line = line.lstrip("\t")
        match = re.match(r"^[0-9a-fA-F]{8}\s+((?:[0-9a-fA-F]{2}\s*)+)", line)
        if match:
            current.append(match.group(1).replace(" ", ""))
    if current:
        chunks.append("".join(current))
    return chunks


def tcp_stream_follow(path: Path, stream_id: int, timeout: int = 60) -> dict[str, Any] | None:
    """Follow a TCP stream and return ASCII + Hex directional data.

    Returns ``{stream, nodes, directions}`` where each direction is
    ``{direction, ascii, hex}``. ``None`` if tshark is unavailable or the stream
    does not exist.
    """
    if not shutil.which("tshark"):
        return None
    try:
        ascii_proc = subprocess.run(
            ["tshark", "-r", str(path), "-z", f"follow,tcp,ascii,{int(stream_id)}"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        hex_proc = subprocess.run(
            ["tshark", "-r", str(path), "-z", f"follow,tcp,hex,{int(stream_id)}"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    ascii_out = (ascii_proc.stdout or "") + (ascii_proc.stderr or "")
    hex_out = (hex_proc.stdout or "") + (hex_proc.stderr or "")
    if "Node 0:" not in ascii_out:
        return None
    parsed = _parse_follow_ascii(ascii_out)
    hexes = _parse_follow_hex(hex_out)
    directions: list[dict[str, Any]] = []
    for idx, chunk in enumerate(parsed["chunks"]):
        directions.append({
            "direction": f"{idx % 2}" if len(parsed["chunks"]) > 1 else "0",
            "ascii": chunk["ascii"],
            "hex": hexes[idx] if idx < len(hexes) else "",
        })
    return {"stream": str(stream_id), "nodes": parsed["nodes"], "directions": directions}
