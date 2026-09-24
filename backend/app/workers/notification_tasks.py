"""Celery entry points that deliver alerts to their configured channels.

Delivery retries are rescheduled by name through the dispatch port, so a retry
never depends on importing this module. The backoff sequence is unchanged.
"""

import json
import smtplib
from datetime import UTC, datetime, timedelta
from urllib.request import Request, urlopen

from sqlalchemy import or_, select

from app.core.config import settings
from app.core.database import SessionLocal
from app.models import (
    Alert,
    AlertDelivery,
)
from app.workers.celery_app import celery_app
from app.workers.task_names import (
    DELIVER_ALERT,
)


def _delivery_backoff(attempts: int) -> int:
    sequence = [10, 60, 300, 900, 1800]
    if attempts <= 0:
        return sequence[0]
    return sequence[min(attempts - 1, len(sequence) - 1)]


@celery_app.task(name=DELIVER_ALERT)
def deliver_alert_task(alert_id: int) -> None:
    with SessionLocal() as db:
        alert = db.get(Alert, alert_id)
        if not alert:
            return
        now = datetime.now(UTC)
        rows = db.scalars(
            select(AlertDelivery).where(
                AlertDelivery.alert_id == alert_id,
                AlertDelivery.status.in_(["pending", "retrying"]),
                or_(AlertDelivery.next_attempt_at.is_(None), AlertDelivery.next_attempt_at <= now),
            )
        ).all()
        payload = {
            "alert_id": alert.id,
            "title": alert.title,
            "summary": alert.summary,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "status": alert.status,
            "finding_id": alert.finding_id,
            "incident_id": alert.incident_id,
            "probe_id": alert.probe_id,
            "occurrence_count": alert.occurrence_count,
            "last_seen": alert.last_seen.isoformat() if alert.last_seen else "",
        }
        for row in rows:
            row.attempts += 1
            try:
                if row.channel == "webhook":
                    request = Request(
                        row.target,
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    if settings.webhook_secret:
                        request.add_header("X-Webhook-Secret", settings.webhook_secret)
                    with urlopen(request, timeout=10) as response:
                        response.read(1024)
                elif row.channel == "smtp":
                    import email.message

                    message = email.message.EmailMessage()
                    message["Subject"] = f"[数据安全监测检测工具箱] {alert.severity} {alert.title}"
                    message["From"] = settings.smtp_from or settings.smtp_user
                    message["To"] = row.target
                    message.set_content(json.dumps(payload, ensure_ascii=False, indent=2))
                    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
                        smtp.starttls()
                        if settings.smtp_user:
                            smtp.login(settings.smtp_user, settings.smtp_password)
                        smtp.send_message(message)
                else:
                    raise ValueError(f"unknown channel: {row.channel}")
                row.status = "sent"
                row.last_error = ""
                row.sent_at = now
                row.next_attempt_at = None
            except Exception as exc:  # noqa: BLE001
                max_attempts = row.max_attempts or settings.alert_delivery_max_attempts
                row.last_error = str(exc)[:2000]
                if row.attempts >= max_attempts:
                    row.status = "failed_permanent"
                    row.next_attempt_at = None
                else:
                    row.status = "retrying"
                    row.next_attempt_at = now + timedelta(seconds=_delivery_backoff(row.attempts))
                    deliver_alert_task.apply_async(
                        args=[alert_id], countdown=_delivery_backoff(row.attempts)
                    )
        db.commit()
