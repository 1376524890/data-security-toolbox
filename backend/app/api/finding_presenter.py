"""finding presenter responsibilities."""

from __future__ import annotations

from typing import Any

from app.models import DetectionFinding

ATTACK_MAP: dict[str, dict[str, str]] = {
    "NETWORK_PORT_SCAN": {
        "tactic": "Reconnaissance",
        "technique": "Network Service Scanning",
        "technique_id": "T1046",
    },
    "NET_C2_BEACON_001": {
        "tactic": "Command and Control",
        "technique": "Application Layer Protocol",
        "technique_id": "T1071",
    },
    "PROTO_DNS_TUNNEL_001": {
        "tactic": "Exfiltration",
        "technique": "DNS",
        "technique_id": "T1048.003",
    },
    "PROTO_DNS_TXT_001": {
        "tactic": "Exfiltration",
        "technique": "DNS",
        "technique_id": "T1048.003",
    },
    "PROTO_HTTP_UA_001": {
        "tactic": "Initial Access",
        "technique": "User Agent Fingerprinting",
        "technique_id": "T1595.002",
    },
    "PROTO_HTTP_UPLOAD_001": {
        "tactic": "Persistence",
        "technique": "Web Shell",
        "technique_id": "T1505.003",
    },
    "DATA_PII_001": {
        "tactic": "Collection",
        "technique": "Data from Information Repositories",
        "technique_id": "T1213",
    },
    "DATA_SECRET_001": {
        "tactic": "Credential Access",
        "technique": "Unsecured Credentials",
        "technique_id": "T1552",
    },
    "DATA_YARA_001": {
        "tactic": "Defense Evasion",
        "technique": "Obfuscated Files or Information",
        "technique_id": "T1027",
    },
    "DATA_CLASSIFIED_001": {
        "tactic": "Collection",
        "technique": "Data from Information Repositories",
        "technique_id": "T1213",
    },
    "DATA_REDHEAD_001": {
        "tactic": "Collection",
        "technique": "Data from Information Repositories",
        "technique_id": "T1213",
    },
    "ASSET_PUBLIC_DB_001": {
        "tactic": "Initial Access",
        "technique": "Exposed Database",
        "technique_id": "T1190",
    },
    "ASSET_DB_WEAK_AUTH_001": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
    },
    "ASSET_PUBLIC_WEB_001": {
        "tactic": "Initial Access",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
    },
}


def _attack(rule_id: str) -> dict[str, str]:
    return ATTACK_MAP.get(rule_id, {"tactic": "", "technique": "", "technique_id": ""})


def _serialize_detection(item: DetectionFinding) -> dict[str, Any]:
    attack = _attack(item.rule_id)
    return {
        "id": item.id,
        "task_id": item.task_id,
        "target_type": item.target_type,
        "target_id": item.target_id,
        "engine": item.engine,
        "rule_id": item.rule_id,
        "severity": item.severity,
        "confidence": item.confidence,
        "evidence": item.evidence,
        "recommendation": item.recommendation,
        "risk_score": item.risk_score,
        "risk_level": item.risk_level,
        "timestamp": item.timestamp,
        "tactic": attack["tactic"],
        "technique": attack["technique"],
        "technique_id": attack["technique_id"],
        "created_at": item.created_at,
    }
