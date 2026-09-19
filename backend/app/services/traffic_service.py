from collections import Counter, defaultdict
from typing import Any

from app.core.config import settings


def traffic_trend(packets: list[dict[str, Any]], bucket_seconds: int = 10) -> list[dict[str, Any]]:
    buckets: dict[int, dict[str, float | int]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "flows": set()})
    for packet in packets:
        bucket = int(float(packet.get("timestamp", 0)) // bucket_seconds) * bucket_seconds
        buckets[bucket]["packets"] += 1
        buckets[bucket]["bytes"] += int(packet.get("length", 0))
        buckets[bucket]["flows"].add((packet.get("src_ip"), packet.get("dst_ip"), packet.get("protocol")))
    return [{"time": key, "packets": value["packets"], "bytes": value["bytes"], "flows": len(value["flows"])} for key, value in sorted(buckets.items())]


def top_n_communication(flows: list[dict[str, Any]], n: int = 10) -> list[dict[str, Any]]:
    ranked = sorted(flows, key=lambda item: item.get("bytes", 0), reverse=True)
    return ranked[:n]


def protocol_distribution(flows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(item.get("protocol", "other") for item in flows).most_common())


def host_behavior(flows: list[dict[str, Any]], packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    for flow in flows:
        for ip, role in ((flow["src_ip"], "source"), (flow["dst_ip"], "destination")):
            entry = hosts.setdefault(ip, {"ip": ip, "packets": 0, "bytes": 0, "destinations": set(), "protocols": set()})
            entry["packets"] += flow.get("packets", 0)
            entry["bytes"] += flow.get("bytes", 0)
            entry["destinations"].add(flow["dst_ip"] if role == "source" else flow["src_ip"])
            entry["protocols"].add(flow.get("protocol", "other"))
    return [
        {"ip": key, "packets": value["packets"], "bytes": value["bytes"], "destinations": len(value["destinations"]), "protocols": sorted(value["protocols"])}
        for key, value in sorted(hosts.items(), key=lambda item: item[1]["bytes"], reverse=True)
    ]


def _busiest_port_window(flows: list[dict[str, Any]], window_seconds: int) -> tuple[list[int], float, float]:
    """Unique destination ports in the busiest real time window of one source.

    A capture-wide ``port_count`` counts every host's traffic together, so 21
    hosts touching one port each used to look like one scanner touching 21. This
    slides the window over the flow start times and returns the densest one, so
    the count matches the window the evidence claims.
    """
    timed = sorted(
        ((float(flow.get("start_time") or flow.get("end_time") or 0), int(flow.get("dst_port") or 0))
         for flow in flows if int(flow.get("dst_port") or 0)),
        key=lambda item: item[0],
    )
    counts: dict[int, int] = {}
    best: list[int] = []
    best_start = best_end = 0.0
    left = 0
    for timestamp, port in timed:
        counts[port] = counts.get(port, 0) + 1
        while timestamp - timed[left][0] > window_seconds:
            left_port = timed[left][1]
            counts[left_port] -= 1
            if counts[left_port] <= 0:
                del counts[left_port]
            left += 1
        if len(counts) > len(best):
            best = sorted(counts)
            best_start, best_end = timed[left][0], timestamp
    return best, best_start, best_end


def detect_anomalies(flows: list[dict[str, Any]], packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    window = int(settings.port_scan_window_seconds)
    by_src: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"flows": [], "dst_ips": set(), "bytes": 0, "packets": 0})
    for flow in flows:
        entry = by_src[flow["src_ip"]]
        entry["flows"].append(flow)
        entry["dst_ips"].add(flow["dst_ip"])
        entry["bytes"] += flow["bytes"]
        entry["packets"] += flow["packets"]
    for src, stats in by_src.items():
        ports, window_start, window_end = _busiest_port_window(stats["flows"], window)
        if len(ports) >= settings.port_scan_ports_threshold:
            anomalies.append({"rule": "NETWORK_PORT_SCAN", "severity": "High", "description": f"{src} 在 {window} 秒窗口内访问了 {len(ports)} 个不同端口，疑似端口扫描", "evidence": {"src": src, "dst_ports": ports, "port_count": len(ports), "window": window, "window_start": round(window_start, 3), "window_end": round(window_end, 3), "packet_count": stats["packets"]}})
        if len(stats["dst_ips"]) >= 10 and stats["bytes"] > 10_000_000:
            anomalies.append({"rule": "broad_communication", "severity": "Medium", "description": f"{src} 与多个目标进行大流量通信", "evidence": {"src_ip": src, "destinations": len(stats["dst_ips"]), "bytes": stats["bytes"]}})
    if packets:
        rate = len(packets) / max(packets[-1]["timestamp"] - packets[0]["timestamp"], 1)
        if rate > 500:
            anomalies.append({"rule": "high_packet_rate", "severity": "Medium", "description": "短时间内包速率过高", "evidence": {"packet_rate": rate}})
    return anomalies
