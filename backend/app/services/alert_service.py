from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Alert, AlertDelivery, DetectionFinding, Incident

ALERTS_CHANNEL = "security.alerts"


def _redis_client() -> redis.Redis | None:
    try:
        client = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=1, socket_timeout=1)
        client.ping()
        return client
    except Exception:
        return None


def alert_fingerprint(rule_id: str, source: str, asset: str, ioc: str) -> str:
    payload = f"{rule_id}|{source}|{asset}|{ioc}".encode()
    return hashlib.sha256(payload).hexdigest()


def _asset_from_finding(finding: DetectionFinding) -> str:
    evidence = finding.evidence or {}
    for key in ("asset", "src_ip", "dst_ip", "dest_ip", "ip", "host", "hostname"):
        value = evidence.get(key)
        if value:
            return str(value)
    record = evidence.get("record")
    if isinstance(record, dict):
        for key in ("src_ip", "dst_ip", "dest_ip", "host", "hostname"):
            if record.get(key):
                return str(record[key])
    return ""


def _ioc_from_finding(finding: DetectionFinding) -> str:
    evidence = finding.evidence or {}
    ioc = evidence.get("ioc")
    if isinstance(ioc, dict):
        return str(ioc.get("value") or "")
    for key in ("value", "query", "qname", "rrname", "domain", "url", "uri", "matched_iocs"):
        value = evidence.get(key)
        if value:
            return str(value)
    record = evidence.get("record")
    if isinstance(record, dict):
        for key in ("query", "qname", "rrname", "domain", "host", "url", "uri"):
            if record.get(key):
                return str(record[key])
    return ""


def _policy_allows(severity: str, risk_score: float) -> bool:
    policy = settings.alert_policy or {}
    if severity == "Critical":
        return bool(policy.get("critical_finding_immediate", True))
    if severity == "High":
        return risk_score >= float(policy.get("high_finding_min_risk", 60))
    if severity == "Medium":
        return bool(policy.get("medium_notify", False))
    return False


def create_finding_alert(db: Session, finding: DetectionFinding, probe_id: int | None = None) -> Alert | None:
    if not _policy_allows(finding.severity, finding.risk_score):
        return None
    asset = _asset_from_finding(finding)
    ioc = _ioc_from_finding(finding)
    fp = alert_fingerprint(finding.rule_id, finding.engine, asset, ioc)
    alert = db.scalar(select(Alert).where(Alert.fingerprint == fp))
    now = datetime.now(UTC)
    if alert:
        alert.occurrence_count += 1
        alert.last_seen = now
        alert.risk_score = max(alert.risk_score, finding.risk_score)
        alert.severity = finding.severity if alert.severity != "Critical" else "Critical"
        return alert
    title = finding.rule_id
    if asset:
        title = f"{finding.severity} {finding.rule_id} {asset}"
    alert = Alert(
        fingerprint=fp,
        finding_id=finding.id,
        probe_id=probe_id,
        severity=finding.severity,
        risk_score=finding.risk_score,
        title=title,
        summary=finding.recommendation or f"{finding.engine} detected {finding.rule_id}",
        status="new",
        first_seen=now,
        last_seen=now,
        occurrence_count=1,
        source=finding.engine,
    )
    db.add(alert)
    db.flush()
    return alert


def create_incident_alert(db: Session, incident: Incident) -> Alert | None:
    policy = settings.alert_policy or {}
    if incident.severity == "Critical":
        allowed = bool(policy.get("critical_incident_immediate", True))
    elif incident.severity == "High":
        allowed = incident.risk_score >= float(policy.get("high_incident_min_risk", 60))
    else:
        allowed = bool(policy.get("medium_notify", False))
    if not allowed:
        return None
    evidence = incident.evidence or {}
    asset = str(evidence.get("asset") or "")
    ioc = str(evidence.get("ioc") or "")
    fp = alert_fingerprint("INCIDENT", incident.source, asset, ioc)
    alert = db.scalar(select(Alert).where(Alert.fingerprint == fp))
    now = datetime.now(UTC)
    if alert:
        alert.occurrence_count += 1
        alert.last_seen = now
        alert.risk_score = max(alert.risk_score, incident.risk_score)
        return alert
    alert = Alert(
        fingerprint=fp,
        incident_id=incident.id,
        probe_id=incident.probe_id,
        severity=incident.severity,
        risk_score=incident.risk_score,
        title=incident.title,
        summary=str(evidence.get("stages") or "") or incident.title,
        status="new",
        first_seen=now,
        last_seen=now,
        occurrence_count=1,
        source=incident.source,
    )
    db.add(alert)
    db.flush()
    return alert


def queue_deliveries(db: Session, alert_id: int) -> list[AlertDelivery]:
    targets: list[tuple[str, str]] = []
    if settings.webhook_url:
        targets.append(("webhook", settings.webhook_url))
    if settings.smtp_host and settings.smtp_to:
        targets.append(("smtp", settings.smtp_to))
    rows: list[AlertDelivery] = []
    for channel, target in targets:
        delivery = AlertDelivery(alert_id=alert_id, channel=channel, target=target, status="pending")
        db.add(delivery)
        rows.append(delivery)
    return rows


def publish_alert(alert_id: int) -> bool:
    client = _redis_client()
    if not client:
        return False
    try:
        client.publish(ALERTS_CHANNEL, json.dumps({"alert_id": alert_id, "type": "alert.created", "ts": datetime.now(UTC).isoformat()}))
        return True
    except Exception:
        return False


def serialize_alert(alert: Alert, db: Session | None = None) -> dict[str, Any]:
    return {
        "id": alert.id,
        "fingerprint": alert.fingerprint,
        "finding_id": alert.finding_id,
        "incident_id": alert.incident_id,
        "probe_id": alert.probe_id,
        "severity": alert.severity,
        "risk_score": alert.risk_score,
        "title": alert.title,
        "summary": alert.summary,
        "status": alert.status,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "occurrence_count": alert.occurrence_count,
        "source": alert.source,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
    }
