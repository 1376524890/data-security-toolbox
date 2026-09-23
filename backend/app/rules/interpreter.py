import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult


@dataclass
class Rule:
    rule_id: str
    title: str
    severity: str
    confidence: float
    condition: str
    recommendation: str = ""
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def load_rules(path: Path) -> list[Rule]:
    rules: list[Rule] = []
    for file_path in sorted(path.glob("*.yaml")) if path.exists() else []:
        document = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        if not isinstance(document, list):
            document = [document]
        for item in document:
            rules.append(Rule(
                rule_id=item["rule_id"],
                title=item.get("title", item["rule_id"]),
                severity=item.get("severity", "Medium"),
                confidence=float(item.get("confidence", 0.8)),
                condition=item["condition"],
                recommendation=item.get("recommendation", ""),
                source=item.get("source", file_path.name),
                metadata=item.get("metadata", {}),
            ))
    return rules


def _metrics(context: DetectionContext) -> dict[str, Any]:
    """Metrics a network rule may name, each describing what its rule claims.

    Two families live here and they are not interchangeable:

    * per-host / per-conversation - ``port_count``, ``dst_count``, ``dst_bytes``,
      ``packet_rate``. These answer "did one host do something abnormal", which
      is what every rule in ``rules/network`` asks. They are maxima over hosts or
      conversations, never sums.
    * whole-capture aggregates - ``capture_*``. A rule that uses one of these is
      saying "this segment carried X", which is not evidence of an attack: a
      64 MiB segment from a busy link always carries tens of megabytes and
      thousands of packets, so a capture-wide threshold fires on every segment.
    """
    from app.core.config import settings
    from app.services.traffic_scope import filter_flows, filter_packets
    from app.services.traffic_service import _busiest_port_window

    flows, _ignored_flows = filter_flows(context.flows or [])
    packets, _ignored_packets = filter_packets(context.packets or [])
    window = int(context.data.get("port_scan_window_seconds") or settings.port_scan_window_seconds)
    by_src: dict[str, dict[str, Any]] = {}
    by_pair: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for flow in flows:
        src = flow.get("src_ip", "")
        dst = flow.get("dst_ip", "")
        stats = by_src.setdefault(
            src, {"flows": [], "dst_ports": set(), "dst_ips": set(), "bytes": 0, "packets": 0}
        )
        stats["flows"].append(flow)
        stats["dst_ports"].add(flow.get("dst_port", 0))
        stats["dst_ips"].add(dst)
        stats["bytes"] += int(flow.get("bytes", 0))
        stats["packets"] += int(flow.get("packets", 0))
        by_pair.setdefault((src, dst), []).append(flow)

    duration = 0.0
    if packets:
        duration = float(packets[-1].get("timestamp", 0)) - float(packets[0].get("timestamp", 0))

    def _conversation_rate(flow: dict[str, Any]) -> float:
        span = float(flow.get("end_time") or 0) - float(flow.get("start_time") or 0)
        return int(flow.get("packets", 0)) / max(span, 0.001)

    busiest_rate = max((_conversation_rate(flow) for flow in flows), default=0.0)
    # "How far did one host spread": the source with the most distinct
    # destinations, and what that same source moved while doing it. Keeping the
    # pair together is what makes "broad communication" mean one host with real
    # traffic behind it, rather than a busy segment.
    spread_src = max(by_src.values(), key=lambda item: len(item["dst_ips"]), default=None)
    metrics: dict[str, Any] = {
        "flow_count": len(flows),
        "packet_count": len(packets),
        # Per conversation: the rate a single flow sustained. See the docstring.
        "packet_rate": busiest_rate,
        "capture_packet_rate": len(packets) / max(duration, 0.001),
        "total_bytes": sum(int(flow.get("bytes", 0)) for flow in flows),
        # The single-host questions a scan/横向 rule asks. Summing every host's
        # ports together is what made 21 hosts x 1 port look like a port scan,
        # and counting a server's replies (one flow per client, each with a
        # different ephemeral destination port) is what made every DNS server
        # look like one too - so the count is per (source, destination) pair and
        # uses the service side of the conversation.
        "port_count": 0,
        "dst_count": len(spread_src["dst_ips"]) if spread_src else 0,
        "dst_bytes": int(spread_src["bytes"]) if spread_src else 0,
        "capture_port_count": len({flow.get("dst_port", 0) for flow in flows}),
        "capture_dst_count": len({flow.get("dst_ip", "") for flow in flows}),
        "src_count": len(by_src),
    }
    for pair_flows in by_pair.values():
        windowed, _, _ = _busiest_port_window(pair_flows, window)
        metrics["port_count"] = max(metrics["port_count"], len(windowed))
    for src, stats in by_src.items():
        metrics[f"src:{src}:ports"] = max(
            (len(_busiest_port_window(pair_flows, window)[0])
             for (pair_src, _dst), pair_flows in by_pair.items() if pair_src == src),
            default=0,
        )
        metrics[f"src:{src}:ports_total"] = len(stats["dst_ports"])
        metrics[f"src:{src}:dsts"] = len(stats["dst_ips"])
        metrics[f"src:{src}:bytes"] = stats["bytes"]
        metrics[f"src:{src}:packets"] = stats["packets"]
    return metrics


def _resolve(context: DetectionContext, name: str) -> Any:
    metrics = _metrics(context)
    if name in metrics:
        return metrics[name]
    if name.startswith("src:"):
        return metrics.get(name, 0)
    return context.data.get(name, 0)


def _compare(left: Any, op: str, right: Any) -> bool:
    if op == ">":
        return float(left) > float(right)
    if op == ">=":
        return float(left) >= float(right)
    if op == "<":
        return float(left) < float(right)
    if op == "<=":
        return float(left) <= float(right)
    if op == "==":
        return str(left) == str(right)
    if op == "in":
        return str(left) in str(right)
    return False


def _eval_condition(condition: str, context: DetectionContext) -> bool:
    if " or " in condition:
        return any(_eval_condition(part.strip(), context) for part in condition.split(" or "))
    if " and " in condition:
        return all(_eval_condition(part.strip(), context) for part in condition.split(" and "))
    match = re.match(r"^([A-Za-z0-9_:.\-]+)\s*(>=|<=|>|<|==|in)\s*(.+)$", condition.strip())
    if not match:
        return False
    name, op, raw_right = match.groups()
    right: Any = raw_right.strip().strip('"\'')
    try:
        right = float(right)
    except ValueError:
        pass
    return _compare(_resolve(context, name), op, right)


def interpret_rules(context: DetectionContext, rule_dir: Path,
                    engine: str) -> list[DetectionResult]:
    results: list[DetectionResult] = []
    for rule in load_rules(rule_dir):
        if _eval_condition(rule.condition, context):
            results.append(DetectionResult(
                engine=engine,
                rule_id=rule.rule_id,
                severity=rule.severity,
                confidence=rule.confidence,
                evidence={"rule": rule.title, "condition": rule.condition, "metrics": _metrics(context)},
                recommendation=rule.recommendation,
            ).normalize())
    return results
