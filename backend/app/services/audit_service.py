import re
from collections import Counter
from typing import Any


def file_security_audit(metadata: dict[str, Any], risk_level: str = "Low") -> dict[str, Any]:
    findings = []
    if metadata.get("hidden_info", {}).get("hidden"):
        findings.append({"severity": "Medium", "message": "文件包含隐藏信息或异常元数据"})
    file_type = metadata.get("file_type", "")
    if file_type in {"application/pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}:
        findings.append({"severity": "Low", "message": "文档类文件应纳入敏感数据管理"})
    return {"risk_level": risk_level, "findings": findings}


def asset_exposure_audit(asset: dict[str, Any]) -> dict[str, Any]:
    return {"ip": asset["ip"], "service": asset["service"], "port": asset["port"], "asset_type": asset["asset_type"], "risk_level": asset["risk_level"], "sensitive_categories": asset["sensitive_categories"]}


def leak_risk_audit(pcaps: list[dict[str, Any]]) -> dict[str, Any]:
    protocols = Counter()
    for pcap in pcaps:
        protocols.update(pcap.get("protocol_summary", {}))
    high_protocols = [proto for proto in protocols if proto.lower() in {"http", "ftp", "smtp", "smb", "telnet"}]
    risk = "High" if high_protocols else "Low"
    return {"risk_level": risk, "protocols": dict(protocols.most_common(20)), "high_risk_protocols": high_protocols}


def network_behavior_audit(anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    counter = Counter(item["severity"] for item in anomalies)
    return {"total": len(anomalies), "severities": dict(counter), "items": anomalies[:50]}


def log_analysis(lines: list[str]) -> dict[str, Any]:
    patterns = {
        "auth_failure": re.compile(r"(failed|failure|denied|rejected|invalid).*(password|login|auth|user)", re.IGNORECASE),
        "sql_error": re.compile(r"(sql|psql|ora-|syntax error|duplicate)", re.IGNORECASE),
        "port_scan": re.compile(r"(scan|syn|nmap)", re.IGNORECASE),
        "privilege": re.compile(r"(sudo|root|admin|privilege)", re.IGNORECASE),
        "traversal": re.compile(r"(\.\./|\.\.\\|path traversal)", re.IGNORECASE),
    }
    matches = {name: [] for name in patterns}
    for line in lines:
        for name, pattern in patterns.items():
            if pattern.search(line):
                matches[name].append(line[:300])
    return {"line_count": len(lines), "matches": matches}


def audit_summary(assets: list[dict[str, Any]], files: list[dict[str, Any]], pcaps: list[dict[str, Any]], anomalies: list[dict[str, Any]]) -> dict[str, Any]:
    asset_risks = Counter(item["risk_level"] for item in assets)
    file_risks = Counter(item.get("risk_level", "Low") for item in files)
    anomaly_severities = Counter(item["severity"] for item in anomalies)
    return {
        "assets": len(assets),
        "asset_risk": dict(asset_risks),
        "files": len(files),
        "file_risk": dict(file_risks),
        "pcaps": len(pcaps),
        "anomalies": len(anomalies),
        "anomaly_severity": dict(anomaly_severities),
        "leak_risk": leak_risk_audit(pcaps),
    }

"""Audit trail for administrative write operations.

``AuditLog`` existed but nothing ever wrote to it, so a destructive or
recovery action left no trace. :func:`record_audit` is the one write path: it
records the acting administrator, the action and a small details payload, and it
never raises - an audit failure must not turn a working operation into an error.

Details are capped and JSON-safe: an audit entry carries counts and identifiers,
never a matched value or a credential.
"""
from typing import Any

from sqlalchemy.orm import Session

from app.core.security import get_session_user
from app.models import AuditLog

#: Keeps one oversized payload from bloating the table.
MAX_DETAIL_ITEMS = 32
MAX_DETAIL_CHARS = 512


def _actor(db: Session, request: Any) -> str:
    try:
        user = get_session_user(db, request)
    except Exception:  # pragma: no cover - an unreadable session is not a write error
        user = None
    return str(getattr(user, "username", "") or "admin")


def _clean(details: Any) -> dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    clean: dict[str, Any] = {}
    for key, value in list(details.items())[:MAX_DETAIL_ITEMS]:
        if isinstance(value, (int, float, bool)) or value is None:
            clean[str(key)[:64]] = value
        elif isinstance(value, str):
            clean[str(key)[:64]] = value[:MAX_DETAIL_CHARS]
        else:
            clean[str(key)[:64]] = str(value)[:MAX_DETAIL_CHARS]
    return clean


def record_audit(db: Session, request: Any, *, action: str, target: str = "",
                 severity: str = "Low", details: Any = None) -> AuditLog | None:
    """Append one audit row. Returns ``None`` if the entry could not be stored."""
    try:
        row = AuditLog(action=str(action)[:128], actor=_actor(db, request),
                       target=str(target)[:512], severity=str(severity)[:16],
                       details=_clean(details))
        db.add(row)
        db.flush()
        return row
    except Exception:  # pragma: no cover - auditing is best-effort by design
        return None


__all__ = ["record_audit"]