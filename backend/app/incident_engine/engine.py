from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import hashlib
from typing import Any

from app.domain.evidence_identity import (
    ASSET_SOURCE_FIELDS,
    asset_identity,
    evidence_asset_keys,
    evidence_ioc_keys,
    evidence_primary_asset,
    short_asset,
)
from app.engine.core.result import DetectionResult

#: Compatibility re-exports: these identity helpers used to live here, and
#: api/v1.py, incident_engine/attribution.py and the tests still import them
#: from this module. Engine behaviour itself no longer depends on the names.
__all__ = [
    "IncidentEngine",
    "ASSET_SOURCE_FIELDS",
    "asset_identity",
    "evidence_asset_keys",
    "evidence_ioc_keys",
    "evidence_primary_asset",
    "short_asset",
]

_short_asset = short_asset
_asset_identity = asset_identity


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
    return evidence_asset_keys(finding.evidence)


def _ioc_keys(finding: DetectionResult) -> list[str]:
    return evidence_ioc_keys(finding.evidence)


def _probe_key(finding: DetectionResult) -> str:
    evidence = finding.evidence
    if evidence.get("probe_id"):
        return str(evidence["probe_id"]).lower()
    if isinstance(evidence.get("record"), dict) and evidence["record"].get("probe_id"):
        return str(evidence["record"]["probe_id"]).lower()
    return ""


# Attack stage is DECLARED by the rule, never inferred from evidence text. The
# previous implementation searched the whole evidence dict for keywords, and
# because every persisted finding carries ``probe_id`` the "probe" keyword
# filed DLP transfers and C2 beacons as reconnaissance. Only the rule id takes
# part now; anything unnamed stays "unknown".
STAGE_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("recon", ("scan", "recon", "fingerprint", "discover", "enumerat", "public", "exposure")),
    ("exploit", ("exploit", "upload", "webshell", "inject", "traversal", "yara", "nuclei", "cve")),
    ("credential", ("credential", "password", "secret", "token", "auth", "weak")),
    ("c2", ("c2", "beacon", "tunnel", "ioc", "dga", "dns")),
    ("exfil", ("exfil", "transfer", "pii", "leak", "large", "dlp")),
    ("impact", ("ransom", "destroy", "impact", "wiper")),
)

# Rule ids whose stage the keyword scan cannot infer correctly on its own.
STAGE_RULE_OVERRIDES: dict[str, str] = {
    "PROTO_HTTP_UA_001": "recon",
    "ZEK_HTTP_UA_001": "recon",
    "ZEK_DNS_NXDOMAIN_001": "recon",
    "ZEK_HTTP_ERROR_001": "exploit",
    "ZEK_WEIRD_001": "exploit",
    "ZEK_FILE_SUSPICIOUS_001": "exploit",
    "ZEK_TLS_WEAK_001": "credential",
    "ZEK_TLS_INVALID_001": "credential",
    "DATA_YARA_001": "exploit",
    "COMP_WEAK_PROTOCOL_001": "credential",
}


def _stage(finding: DetectionResult) -> str:
    rule_id = finding.rule_id
    override = STAGE_RULE_OVERRIDES.get(rule_id)
    if override:
        return override
    rule = rule_id.lower()
    for name, tokens in STAGE_KEYWORDS:
        if any(token in rule for token in tokens):
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
    fingerprint: str = ""
    source: str = "pipeline"
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
        ordered = sorted(findings, key=lambda item: (_parse_ts(item.timestamp), item.rule_id))
        buckets: dict[str, list[DetectionResult]] = defaultdict(list)
        for item in ordered:
            for key in self._correlation_keys(item):
                buckets[key].append(item)
        incidents: list[Incident] = []
        seen: set[tuple[str, ...]] = set()
        for key, items in sorted(buckets.items(), key=lambda item: len(item[1]), reverse=True):
            for cluster in self._time_clusters(items, window_seconds):
                if len(cluster) < 2:
                    continue
                asset = self._asset_label(cluster, key)
                # One incident can touch several hosts (a scan source plus its
                # targets). ``asset`` stays the display label, ``assets`` is
                # every host in the cluster so each asset page can find it.
                assets = sorted({value for item in cluster for value in _asset_keys(item)})
                ioc = self._ioc_label(cluster, key)
                stages = sorted({_stage(item) for item in cluster})
                if len(stages) < 2 and not ioc and not asset:
                    continue
                signature = tuple(sorted(self._finding_signature(item) for item in cluster))
                if signature in seen:
                    continue
                seen.add(signature)
                score = max(item.risk_score for item in cluster)
                probe = sorted({_probe_key(item) for item in cluster if _probe_key(item)})
                probe_id = probe[0] if probe else ""
                bucket = self._time_bucket(cluster, window_seconds)
                fingerprint = self._fingerprint(probe_id, asset, ioc, bucket)
                incidents.append(Incident(
                    id=f"INC-{asset or ioc or 'global'}-{len(incidents) + 1}",
                    title=self._title(cluster, asset, ioc),
                    severity=_severity(cluster),
                    confidence=round(sum(item.confidence for item in cluster) / len(cluster), 3),
                    fingerprint=fingerprint,
                    findings=[item.to_dict() for item in cluster],
                    evidence={
                        "asset": asset,
                        "assets": assets,
                        "ioc": ioc,
                        "probe_id": probe_id,
                        "stages": stages,
                        "finding_ids": [item.rule_id for item in cluster],
                        "window_seconds": window_seconds,
                    },
                    risk_score=score,
                    risk_level=self._level(score),
                ))
        return incidents[:100]

    @staticmethod
    def _time_bucket(items: list[DetectionResult], window_seconds: int) -> int:
        timestamps = [_parse_ts(item.timestamp) for item in items if _parse_ts(item.timestamp)]
        if not timestamps:
            return 0
        window = max(1, int(window_seconds))
        return int(min(timestamps) // window)

    @staticmethod
    def _fingerprint(probe: str, asset: str, ioc: str, time_bucket: int) -> str:
        # Identity is the correlation subject (probe/asset/IOC) plus a coarse
        # event-window bucket. Stages are incident STATE, never identity, so
        # adding a stage updates the existing incident instead of forking it.
        payload = f"{probe}|{asset}|{ioc}|{time_bucket}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _correlation_keys(finding: DetectionResult) -> list[str]:
        assets = _asset_keys(finding)
        iocs = _ioc_keys(finding)
        keys = [f"asset:{asset}" for asset in assets] or ["asset:global"]
        if iocs:
            keys.extend(f"ioc:{ioc}" for ioc in iocs)
        if assets and iocs:
            keys.extend(f"asset-ioc:{asset}:{ioc}" for asset in assets for ioc in iocs)
        return list(dict.fromkeys(keys))

    @staticmethod
    def _time_clusters(items: list[DetectionResult], window_seconds: int) -> list[list[DetectionResult]]:
        clusters: list[list[DetectionResult]] = []
        current: list[DetectionResult] = []
        window = max(1, int(window_seconds))
        for item in items:
            ts = _parse_ts(item.timestamp)
            if not current:
                current = [item]
                continue
            first_ts = _parse_ts(current[0].timestamp)
            if first_ts and ts and ts - first_ts > window:
                clusters.append(current)
                current = [item]
            else:
                current.append(item)
        if current:
            clusters.append(current)
        return clusters

    @staticmethod
    def _asset_label(items: list[DetectionResult], key: str) -> str:
        values = sorted({value for item in items for value in _asset_keys(item)})
        return values[0] if values else (key.removeprefix("asset:") if key.startswith("asset:") else "")

    @staticmethod
    def _ioc_label(items: list[DetectionResult], key: str) -> str:
        values = sorted({value for item in items for value in _ioc_keys(item)})
        return values[0] if values else (key.removeprefix("ioc:") if key.startswith("ioc:") else "")

    @staticmethod
    def _finding_signature(item: DetectionResult) -> str:
        return f"{item.engine}|{item.rule_id}|{_parse_ts(item.timestamp)}|{sorted(_asset_keys(item))}|{sorted(_ioc_keys(item))}"

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
