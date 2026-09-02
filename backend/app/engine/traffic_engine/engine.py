import statistics
from collections import defaultdict
from pathlib import Path

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.rules.interpreter import interpret_rules
from app.services.traffic_service import detect_anomalies


class TrafficEngine(DetectionEngine):
    name = "traffic_engine"
    version = "2.0.0"

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        rule_dir = Path(__file__).resolve().parents[2] / "rules" / "network"
        findings = interpret_rules(context, rule_dir)
        legacy = detect_anomalies(context.flows, context.packets)
        for item in legacy:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id=item["rule"],
                severity=item["severity"],
                confidence=0.85,
                evidence={"description": item["description"], **item.get("evidence", {})},
                recommendation="结合会话证据排查异常行为来源和目标。",
            ).normalize())
        for beacon in self._beacon_flows(context):
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="NET_C2_BEACON_001",
                severity="High",
                confidence=0.8,
                evidence=beacon,
                recommendation="排查是否存在 C2 周期性心跳，结合 DNS/HTTP/证书证据确认外联行为。",
            ).normalize())
        return findings

    def _beacon_flows(self, context: DetectionContext) -> list[dict]:
        groups: dict[tuple, list[float]] = defaultdict(list)
        for packet in context.packets:
            key = (packet.get("src_ip"), packet.get("src_port"), packet.get("dst_ip"), packet.get("dst_port"))
            groups[key].append(float(packet.get("timestamp", 0)))
        findings = []
        for key, timestamps in groups.items():
            timestamps.sort()
            if len(timestamps) < 10:
                continue
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
            if not intervals:
                continue
            mean = statistics.fmean(intervals)
            if mean <= 0:
                continue
            stdev = statistics.pstdev(intervals)
            if stdev / mean < 0.2:
                findings.append({"flow": key, "packets": len(timestamps), "interval_mean": round(mean, 4), "interval_stdev": round(stdev, 4), "duration": round(timestamps[-1] - timestamps[0], 4)})
        return findings
