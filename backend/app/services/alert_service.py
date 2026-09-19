from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import redis
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.incident_engine.engine import evidence_primary_asset
from app.models import Alert, AlertDelivery, AlertHit, DetectionFinding, Incident

ALERTS_CHANNEL = "security.alerts"

# Event types emitted over Redis SSE. Frontend only actively notifies on
# ``alert.created`` so ACK / resolve do not re-trigger "new alert" toasts.
EVENT_CREATED = "alert.created"
EVENT_UPDATED = "alert.updated"
EVENT_ACKNOWLEDGED = "alert.acknowledged"
EVENT_RESOLVED = "alert.resolved"
EVENT_SUPPRESSED = "alert.suppressed"


def _redis_client() -> redis.Redis | None:
    try:
        client = redis.Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=1, socket_timeout=1)
        client.ping()
        return client
    except Exception:
        return None


def alert_fingerprint(rule_id: str, source: str, asset: str, ioc: str, probe: str = "") -> str:
    """Suppression identity: rule + engine + probe + subject.

    The probe is part of the identity because the same rule firing on two probes
    is two observations, not one. It is appended only when known so fingerprints
    written before probes were tracked keep suppressing correctly.
    """
    parts = [rule_id, source, asset, ioc]
    if probe:
        parts.append(f"probe:{probe}")
    payload = "|".join(parts).encode()
    return hashlib.sha256(payload).hexdigest()


def _asset_from_finding(finding: DetectionFinding) -> str:
    """The host the alert is filed under, via the shared asset resolver.

    The local key scan ignored ``src`` and the rule engine's ``metrics``, so two
    different scan sources both resolved to "" and were suppressed into one
    alert. The incident engine resolves assets once; alerts reuse it.
    """
    return evidence_primary_asset(finding.evidence or {})


def _probe_from_finding(finding: DetectionFinding) -> str:
    evidence = finding.evidence or {}
    if evidence.get("probe_id"):
        return str(evidence["probe_id"]).lower()
    record = evidence.get("record")
    if isinstance(record, dict) and record.get("probe_id"):
        return str(record["probe_id"]).lower()
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


def _suppressible(db: Session, fingerprint: str, now: datetime, window_seconds: int) -> Alert | None:
    """Return an existing live alert eligible for occurrence suppression.

    A live alert is ``new`` or ``acknowledged`` and has been seen within the
    suppress window. Resolved or expired alerts are never reused, so a
    recurring attack after resolution produces a fresh Alert instance.
    """
    cutoff = now - timedelta(seconds=window_seconds)
    return db.scalar(
        select(Alert)
        .where(
            Alert.fingerprint == fingerprint,
            Alert.status.in_(["new", "acknowledged"]),
            Alert.last_seen >= cutoff,
        )
        .order_by(Alert.last_seen.desc())
        .limit(1)
    )


def _next_instance(db: Session, fingerprint: str) -> int:
    latest = db.scalar(select(func.max(Alert.alert_instance)).where(Alert.fingerprint == fingerprint))
    return int(latest or 0) + 1


def _epoch(value: datetime | None) -> float:
    """Naive/aware-safe sort key for hit timestamps.

    SQLite hands back naive datetimes while a value just written is timezone
    aware; comparing them directly raises ``TypeError``.
    """
    if not value:
        return 0.0
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC).timestamp()
    return value.timestamp()


def _observed_at(finding: DetectionFinding) -> datetime:
    raw = str(finding.timestamp or "").strip()
    if raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _refresh_hit_flags(db: Session, alert_id: int) -> None:
    """Re-point which hit row is the first, the latest and the highest risk."""
    rows = db.scalars(select(AlertHit).where(AlertHit.alert_id == alert_id)).all()
    if not rows:
        return
    first = min(rows, key=lambda hit: (_epoch(hit.observed_at), hit.id or 0))
    latest = max(rows, key=lambda hit: (_epoch(hit.observed_at), hit.id or 0))
    highest = sorted(rows, key=lambda hit: (-float(hit.risk_score or 0.0), _epoch(hit.observed_at)))[0]
    for hit in rows:
        hit.is_first = hit.id == first.id
        hit.is_latest = hit.id == latest.id
        hit.is_highest_risk = hit.id == highest.id


def _record_hit(db: Session, alert: Alert, finding: DetectionFinding, probe: str, asset: str, ioc: str) -> None:
    """Keep this observation behind the alert so suppression hides nothing."""
    hit = db.scalar(select(AlertHit).where(AlertHit.alert_id == alert.id, AlertHit.finding_id == finding.id))
    if hit is None:
        hit = AlertHit(alert_id=alert.id, finding_id=finding.id)
        db.add(hit)
    hit.probe_id = int(probe) if probe.isdigit() else None
    hit.source = finding.engine
    hit.asset = asset
    hit.ioc = ioc
    hit.severity = finding.severity
    hit.risk_score = finding.risk_score
    hit.observed_at = _observed_at(finding)
    db.flush()
    _refresh_hit_flags(db, alert.id)


def list_alert_hits(db: Session, alert_id: int) -> list[dict[str, Any]]:
    """Every observation behind one alert, oldest first.

    Rows whose finding no longer exists are skipped: a hit without its finding
    has no evidence left to show, and SQLite reuses row ids after a delete, so a
    leftover row could otherwise be attributed to an unrelated new alert.
    """
    rows = db.scalars(
        select(AlertHit)
        .where(AlertHit.alert_id == alert_id, AlertHit.finding_id.in_(select(DetectionFinding.id)))
        .order_by(AlertHit.observed_at, AlertHit.id)
    ).all()
    return [
        {
            "id": hit.id,
            "finding_id": hit.finding_id,
            "probe_id": hit.probe_id,
            "source": hit.source,
            "asset": hit.asset,
            "ioc": hit.ioc,
            "severity": hit.severity,
            "risk_score": hit.risk_score,
            "observed_at": hit.observed_at,
            "is_first": hit.is_first,
            "is_latest": hit.is_latest,
            "is_highest_risk": hit.is_highest_risk,
        }
        for hit in rows
    ]


def create_finding_alert(db: Session, finding: DetectionFinding, probe_id: int | None = None) -> tuple[Alert | None, bool]:
    """Create or suppress-update an Alert for a finding.

    Returns ``(alert, created)`` where ``created`` is True only when a brand
    new Alert instance was persisted.
    """
    if not _policy_allows(finding.severity, finding.risk_score):
        return None, False
    probe = str(probe_id) if probe_id is not None else _probe_from_finding(finding)
    asset = _asset_from_finding(finding)
    ioc = _ioc_from_finding(finding)
    fp = alert_fingerprint(finding.rule_id, finding.engine, asset, ioc, probe)
    now = datetime.now(UTC)
    window = int(settings.alert_suppress_window_seconds)
    existing = _suppressible(db, fp, now, window)
    if existing:
        existing.occurrence_count += 1
        existing.last_seen = now
        existing.risk_score = max(existing.risk_score, finding.risk_score)
        existing.severity = finding.severity if existing.severity != "Critical" else "Critical"
        existing.finding_id = existing.finding_id or finding.id
        _record_hit(db, existing, finding, probe, asset, ioc)
        return existing, False
    title = finding.rule_id
    if asset:
        title = f"{finding.severity} {finding.rule_id} {asset}"
    alert = Alert(
        fingerprint=fp,
        correlation_key=fp,
        alert_instance=_next_instance(db, fp),
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
    _record_hit(db, alert, finding, probe, asset, ioc)
    return alert, True


def create_incident_alert(db: Session, incident: Incident) -> tuple[Alert | None, bool]:
    policy = settings.alert_policy or {}
    if incident.severity == "Critical":
        allowed = bool(policy.get("critical_incident_immediate", True))
    elif incident.severity == "High":
        allowed = incident.risk_score >= float(policy.get("high_incident_min_risk", 60))
    else:
        allowed = bool(policy.get("medium_notify", False))
    if not allowed:
        return None, False
    evidence = incident.evidence or {}
    asset = str(evidence.get("asset") or "")
    ioc = str(evidence.get("ioc") or "")
    fp = alert_fingerprint("INCIDENT", incident.source, asset, ioc, str(incident.probe_id or ""))
    now = datetime.now(UTC)
    window = int(settings.alert_suppress_window_seconds)
    existing = _suppressible(db, fp, now, window)
    if existing:
        existing.occurrence_count += 1
        existing.last_seen = now
        existing.risk_score = max(existing.risk_score, incident.risk_score)
        existing.incident_id = existing.incident_id or incident.id
        return existing, False
    alert = Alert(
        fingerprint=fp,
        correlation_key=fp,
        alert_instance=_next_instance(db, fp),
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
    return alert, True


def queue_deliveries(db: Session, alert_id: int) -> list[AlertDelivery]:
    """Create pending deliveries, never duplicating an in-flight channel.

    A new Alert instance creates fresh deliveries; an existing live alert that
    is merely suppress-updated does not spawn duplicate webhook/SMTP rows.
    """
    targets: list[tuple[str, str]] = []
    if settings.webhook_url:
        targets.append(("webhook", settings.webhook_url))
    if settings.smtp_host and settings.smtp_to:
        targets.append(("smtp", settings.smtp_to))
    rows: list[AlertDelivery] = []
    for channel, target in targets:
        existing = db.scalar(
            select(AlertDelivery).where(
                AlertDelivery.alert_id == alert_id,
                AlertDelivery.channel == channel,
                AlertDelivery.target == target,
                AlertDelivery.status.in_(["pending", "retrying"]),
            )
        )
        if existing:
            rows.append(existing)
            continue
        delivery = AlertDelivery(alert_id=alert_id, channel=channel, target=target, status="pending", max_attempts=settings.alert_delivery_max_attempts)
        db.add(delivery)
        rows.append(delivery)
    return rows


def publish_alert(alert_id: int, event_type: str | None = None) -> bool:
    """Publish an alert lifecycle event over Redis.

    If ``event_type`` is omitted it is derived from the alert's persisted
    status so ACK / resolve emit the correct SSE event.
    """
    client = _redis_client()
    if not client:
        return False
    try:
        client.publish(ALERTS_CHANNEL, json.dumps({"alert_id": alert_id, "type": event_type or EVENT_UPDATED, "ts": datetime.now(UTC).isoformat()}))
        return True
    except Exception:
        return False


def event_type_for_status(status: str) -> str:
    mapping = {
        "new": EVENT_CREATED,
        "acknowledged": EVENT_ACKNOWLEDGED,
        "resolved": EVENT_RESOLVED,
        "suppressed": EVENT_SUPPRESSED,
    }
    return mapping.get(status, EVENT_UPDATED)


def serialize_alert(alert: Alert, db: Session | None = None) -> dict[str, Any]:
    return {
        "id": alert.id,
        "fingerprint": alert.fingerprint,
        "correlation_key": alert.correlation_key,
        "alert_instance": alert.alert_instance,
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
