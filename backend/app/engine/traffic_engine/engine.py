import statistics
from collections import defaultdict
from pathlib import Path

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.rules.interpreter import interpret_rules
from app.rules.library import rule_params
from app.services.traffic_service import detect_anomalies
from app.core.config import settings
from app.services.traffic_scope import filter_flows, filter_packets
from app.services.traffic_state import rolling_traffic_state


# A handful of packets 20 ms apart is not a heartbeat. A beacon must last long
# enough and tick slowly enough to be a plausible C2 check-in; the values are
# operator-tunable through the rule library.
BEACON_DEFAULTS = {
    "min_packets": 10,
    "min_duration_seconds": 60.0,
    "min_interval_seconds": 1.0,
    "max_interval_cv": 0.2,
}


class TrafficEngine(DetectionEngine):
    name = "traffic_engine"
    version = "2.0.0"

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        rule_dir = Path(__file__).resolve().parents[2] / "rules" / "network"
        findings = interpret_rules(context, rule_dir, self.name)
        probe = str(context.data.get("probe_id") or context.data.get("probe_name") or "global")
        window = int(context.data.get("port_scan_window_seconds") or settings.port_scan_window_seconds)
        threshold = int(context.data.get("port_scan_ports_threshold") or settings.port_scan_ports_threshold)
        # Loopback and the platform's own management channel are not the network
        # under test; the metrics filter them too, and the rolling state has to
        # see the same traffic or a cross-segment scan could be raised on a host
        # the per-segment pass had already refused to describe.
        flows, _ = filter_flows(context.flows)
        rolling_traffic_state.observe(probe, flows)
        builtin_anomalies = detect_anomalies(context.flows, context.packets)
        for item in builtin_anomalies:
            src = str(item.get("evidence", {}).get("src") or item.get("evidence", {}).get("src_ip") or "")
            if item["rule"] == "NETWORK_PORT_SCAN" and src and rolling_traffic_state.seen(probe, src, item["rule"], window):
                continue
            findings.append(DetectionResult(
                engine=self.name,
                rule_id=item["rule"],
                severity=item["severity"],
                confidence=0.85,
                evidence={"description": item["description"], "window": window, **item.get("evidence", {})},
                recommendation="结合会话证据排查异常行为来源和目标。",
            ).normalize())
        # Cross-segment rolling detection: use the strict sliding-window snapshot.
        # A single segment below the threshold can accumulate across segments and
        # only fire here once the rolling unique-port count reaches the threshold.
        srcs = {str(flow.get("src_ip") or "") for flow in flows if flow.get("src_ip")}
        for src in sorted(srcs):
            snap = rolling_traffic_state.snapshot(probe, src, window)
            if len(snap["dst_ports"]) < threshold:
                continue
            # Only set the cooldown (via seen) once we actually fire a finding.
            if rolling_traffic_state.seen(probe, src, "NETWORK_PORT_SCAN", window):
                continue
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="NETWORK_PORT_SCAN",
                severity="High",
                confidence=0.9,
                evidence={
                    "src": src,
                    "dst_ports": snap["dst_ports"],
                    "port_count": len(snap["dst_ports"]),
                    "window": window,
                    "threshold": threshold,
                    "rolling": True,
                    "packet_count": snap["packets"],
                    "bytes": snap["bytes"],
                },
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
        rule = rule_params("traffic_engine", "NET_C2_BEACON_001", BEACON_DEFAULTS)
        min_packets = int(rule.get("min_packets") or BEACON_DEFAULTS["min_packets"])
        min_duration = float(rule.get("min_duration_seconds") or BEACON_DEFAULTS["min_duration_seconds"])
        min_interval = float(rule.get("min_interval_seconds") or BEACON_DEFAULTS["min_interval_seconds"])
        max_cv = float(rule.get("max_interval_cv") or BEACON_DEFAULTS["max_interval_cv"])
        groups: dict[tuple, list[float]] = defaultdict(list)
        # A beacon check against our own platform's heartbeat/upload would fire on
        # every probe; see traffic_scope.
        packets, _ = filter_packets(context.packets)
        for packet in packets:
            key = (packet.get("src_ip"), packet.get("src_port"), packet.get("dst_ip"), packet.get("dst_port"))
            groups[key].append(float(packet.get("timestamp", 0)))
        findings = []
        for key, timestamps in groups.items():
            timestamps.sort()
            if len(timestamps) < min_packets:
                continue
            duration = timestamps[-1] - timestamps[0]
            if duration < min_duration:
                continue
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
            if not intervals:
                continue
            mean = statistics.fmean(intervals)
            if mean < min_interval:
                continue
            stdev = statistics.pstdev(intervals)
            if stdev / mean >= max_cv:
                continue
            src_ip, src_port, dst_ip, dst_port = key
            findings.append({
                "src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port,
                "packets": len(timestamps), "interval_mean": round(mean, 4),
                "interval_stdev": round(stdev, 4), "duration": round(duration, 4),
                "criteria": {"min_packets": min_packets, "min_duration_seconds": min_duration,
                             "min_interval_seconds": min_interval, "max_interval_cv": max_cv},
            })
        return findings
