from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.engine.core.result import DetectionResult


def _parse_ts(value: Any) -> float:
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        try:
            return float(value)
        except Exception:
            return 0.0


def _asset_keys(finding: DetectionResult) -> list[str]:
    evidence = finding.evidence
    keys = []
    for field_name in ("src_ip", "dest_ip", "dst_ip", "ip", "asset", "host", "hostname", "agent_name"):
        value = evidence.get(field_name)
        if value:
            keys.append(str(value).lower())
    for flow in evidence.get("flow", []):
        if isinstance(flow, dict):
            for field_name in ("src_ip", "dst_ip", "dest_ip"):
                if flow.get(field_name):
                    keys.append(str(flow[field_name]).lower())
    if isinstance(evidence.get("record"), dict):
        record = evidence["record"]
        for field_name in ("src_ip", "dest_ip", "ip", "hostname", "agent.name"):
            value = record.get(field_name)
            if value:
                keys.append(str(value).lower())
    return sorted(set(keys))


def _ioc_keys(finding: DetectionResult) -> list[str]:
    evidence = finding.evidence
    ioc = evidence.get("ioc")
    if isinstance(ioc, dict) and ioc.get("value"):
        return [str(ioc["value"]).lower()]
    keys = []
    for field_name in ("value", "query", "qname", "rrname", "domain", "host", "hostname", "url", "uri"):
        value = evidence.get(field_name)
        if value:
            keys.append(str(value).lower())
    record = evidence.get("record")
    if isinstance(record, dict):
        for field_name in ("query", "qname", "rrname", "domain", "host", "hostname", "url", "uri"):
            if record.get(field_name):
                keys.append(str(record[field_name]).lower())
    return sorted(set(keys))
    return []


def _stage(finding: DetectionResult) -> str:
    rule = finding.rule_id.lower()
    text = f"{rule} {finding.engine} {finding.evidence}".lower()
    stages = [
        ("recon", ("scan", "port_scan", "probe", "fingerprint", "recon")),
        ("exploit", ("exploit", "upload", "webshell", "sql", "rce", "exec", "shell")),
        ("credential", ("credential", "password", "secret", "token", "key", "auth")),
        ("c2", ("c2", "beacon", "tunnel", "dga", "ioc", "misp", "threat")),
        ("exfil", ("exfil", "large", "dns_tunnel", "http_upload", "transfer")),
        ("impact", ("critical", "ransom", "destroy", "impact", "high")),
    ]
    for name, tokens in stages:
        if any(token in text for token in tokens):
            return name
    return "unknown"


def _severity(findings: list[DetectionResult]) -> str:
    weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    return max((item.severity for item in findings), key=lambda item: weights.get(item, 1))


@dataclass
class Incident:
    id: str
    title: str
    severity: str
    confidence: float
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    risk_level: str = "Low"
    status: str = "open"
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IncidentEngine:
    name = "incident_engine"
    version = "1.0.0"

    def correlate(self, findings: list[DetectionResult], window_seconds: int = 3600) -> list[Incident]:
        if not findings:
            return []
        buckets: dict[tuple[str, str], list[DetectionResult]] = defaultdict(list)
        for item in findings:
            assets = _asset_keys(item) or ["global"]
            iocs = _ioc_keys(item) or [""]
            stage = _stage(item)
            for asset in assets:
                for ioc in iocs:
                    buckets[(asset, ioc)].append(item)
            buckets[(assets[0], f"stage:{stage}")].append(item)
        incidents: list[Incident] = []
        for (asset, ioc), items in sorted(buckets.items(), key=lambda item: len(item[1]), reverse=True):
            items = self._within_window(items, window_seconds)
            if len(items) < 2:
                continue
            stages = sorted({_stage(item) for item in items})
            if len(stages) < 2 and not ioc:
                continue
            score = max(item.risk_score for item in items)
            level = self._level(score)
            incidents.append(Incident(
                id=f"INC-{asset or ioc}-{len(incidents) + 1}",
                title=self._title(items, asset, ioc),
                severity=_severity(items),
                confidence=round(sum(item.confidence for item in items) / len(items), 3),
                findings=[item.to_dict() for item in items],
                evidence={"asset": asset, "ioc": ioc, "stages": stages, "finding_ids": [item.rule_id for item in items]},
                risk_score=score,
                risk_level=level,
            ))
        return incidents[:100]

    def _within_window(self, items: list[DetectionResult], window_seconds: int) -> list[DetectionResult]:
        timestamps = sorted(_parse_ts(item.timestamp) for item in items)
        if not timestamps or timestamps[-1] - timestamps[0] <= window_seconds:
            return items
        return items

    def _title(self, items: list[DetectionResult], asset: str, ioc: str) -> str:
        stages = sorted({_stage(item) for item in items})
        if len(stages) > 1:
            return f"攻击链关联：{asset} -> {' -> '.join(stages)}"
        if ioc:
            return f"威胁情报命中：{asset} / {ioc}"
        return f"多事件关联：{asset}"

    def _level(self, score: float) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"
