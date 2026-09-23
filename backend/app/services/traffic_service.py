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
    """Unique *service* ports on one conversation in its busiest real window.

    Two corrections live here, and both are needed for the number to describe a
    port scan rather than ordinary traffic:

    * the count is taken over flows that share a source *and* a destination - a
      capture-wide count made 21 hosts touching one port each look like one
      scanner touching 21;
    * the port counted is the service side of the conversation, not the raw
      destination port, because a reply has the ports swapped. Counting raw
      destination ports made a DNS server answering 35 clients look like a host
      scanning 35 ports.
    """
    from app.services.traffic_scope import service_port

    timed = sorted(
        ((float(flow.get("start_time") or flow.get("end_time") or 0),
          service_port(flow.get("src_port"), flow.get("dst_port")))
         for flow in flows),
        key=lambda item: item[0],
    )
    timed = [(timestamp, port) for timestamp, port in timed if port]
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
    """Built-in network anomalies, computed over the traffic a rule may describe.

    Loopback/self traffic is dropped first (see ``services.traffic_scope``), and
    each metric is per host or per conversation: a capture-wide aggregate scales
    with the segment size, so a threshold on one fires on every segment of a busy
    link and tells an operator nothing.
    """
    from app.services.traffic_scope import filter_flows, filter_packets, service_port

    flows, _ = filter_flows(flows)
    packets, _ = filter_packets(packets)
    anomalies: list[dict[str, Any]] = []
    window = int(settings.port_scan_window_seconds)
    by_pair: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"flows": [], "ports": set(), "bytes": 0, "packets": 0})
    by_src: dict[str, dict[str, Any]] = defaultdict(lambda: {"dst_ips": set(), "bytes": 0})
    for flow in flows:
        src, dst = flow["src_ip"], flow["dst_ip"]
        pair = by_pair[(src, dst)]
        pair["flows"].append(flow)
        pair["ports"].add(service_port(flow.get("src_port"), flow.get("dst_port")))
        pair["bytes"] += flow["bytes"]
        pair["packets"] += flow["packets"]
        by_src[src]["dst_ips"].add(dst)
        by_src[src]["bytes"] += flow["bytes"]
    for (src, dst), stats in by_pair.items():
        ports, window_start, window_end = _busiest_port_window(stats["flows"], window)
        if len(ports) < settings.port_scan_ports_threshold:
            continue
        anomalies.append({
            "rule": "NETWORK_PORT_SCAN",
            "severity": "High",
            "description": (f"{src} 在 {window} 秒窗口内访问了 {dst} 的 {len(ports)} 个不同端口，"
                            "疑似端口扫描"),
            "evidence": {
                "src": src, "dst": dst, "dst_ports": ports, "port_count": len(ports),
                "window": window, "window_start": round(window_start, 3),
                "window_end": round(window_end, 3), "packet_count": stats["packets"],
            },
        })
    for src, stats in by_src.items():
        if len(stats["dst_ips"]) < 10 or stats["bytes"] <= 10_000_000:
            continue
        anomalies.append({
            "rule": "broad_communication",
            "severity": "Medium",
            "description": f"{src} 与多个目标进行大流量通信",
            "evidence": {"src_ip": src, "destinations": len(stats["dst_ips"]),
                         "bytes": stats["bytes"]},
        })
    if packets:
        # Per conversation: the rate one flow sustained. A capture-wide rate is a
        # property of the segment, not of any host in it.
        busiest = max(flows, key=_conversation_rate, default=None)
        if busiest is not None and _conversation_rate(busiest) > 500:
            anomalies.append({
                "rule": "high_packet_rate",
                "severity": "Medium",
                "description": "单个会话包速率过高",
                "evidence": {"packet_rate": _conversation_rate(busiest),
                             "src": busiest.get("src_ip", ""), "dst": busiest.get("dst_ip", ""),
                             "protocol": busiest.get("protocol", "")},
            })
    return anomalies


def _conversation_rate(flow: dict[str, Any]) -> float:
    """One conversation's packet rate; see ``traffic_scope.conversation_rate``.

    The span floor lives there so this metric and the ``NET_RATE_001``
    interpreter metric cannot disagree about what "high packet rate" means - they
    are the same anomaly reported by two producers.
    """
    from app.services.traffic_scope import conversation_rate

    return conversation_rate(flow)
