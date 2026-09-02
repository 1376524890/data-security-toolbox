import math
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
    flows = context.flows or []
    packets = context.packets or []
    by_src: dict[str, dict[str, Any]] = {}
    for flow in flows:
        src = flow.get("src_ip", "")
        stats = by_src.setdefault(src, {"dst_ports": set(), "dst_ips": set(), "bytes": 0, "packets": 0})
        stats["dst_ports"].add(flow.get("dst_port", 0))
        stats["dst_ips"].add(flow.get("dst_ip", ""))
        stats["bytes"] += int(flow.get("bytes", 0))
        stats["packets"] += int(flow.get("packets", 0))
    duration = 0.0
    if packets:
        duration = float(packets[-1].get("timestamp", 0)) - float(packets[0].get("timestamp", 0))
    metrics: dict[str, Any] = {
        "flow_count": len(flows),
        "packet_count": len(packets),
        "packet_rate": len(packets) / max(duration, 0.001),
        "total_bytes": sum(int(flow.get("bytes", 0)) for flow in flows),
        "port_count": len({flow.get("dst_port", 0) for flow in flows}),
        "dst_count": len({flow.get("dst_ip", "") for flow in flows}),
        "src_count": len({flow.get("src_ip", "") for flow in flows}),
    }
    for src, stats in by_src.items():
        metrics[f"src:{src}:ports"] = len(stats["dst_ports"])
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


def interpret_rules(context: DetectionContext, rule_dir: Path) -> list[DetectionResult]:
    results: list[DetectionResult] = []
    for rule in load_rules(rule_dir):
        if _eval_condition(rule.condition, context):
            results.append(DetectionResult(
                engine="rules",
                rule_id=rule.rule_id,
                severity=rule.severity,
                confidence=rule.confidence,
                evidence={"rule": rule.title, "condition": rule.condition, "metrics": _metrics(context)},
                recommendation=rule.recommendation,
            ).normalize())
    return results

