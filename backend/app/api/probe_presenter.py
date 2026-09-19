"""Shared Probe-row serialisation used by more than one route domain."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.datetimes import aware
from app.models import Probe


def serialize_probe(item: Probe) -> dict[str, Any]:
    now = datetime.now(UTC)
    status = item.status
    last_seen = aware(item.last_seen)
    if last_seen:
        age = (now - last_seen).total_seconds()
        if age > 90:
            status = "offline"
        elif status != "degraded" and age < 90:
            status = "online"
    else:
        # Registration alone is not proof that the daemon is running.  A
        # probe must send a heartbeat before it can be shown as online.
        status = "offline"
    return {
        "id": item.id,
        "name": item.name,
        "hostname": item.hostname,
        "ip_address": item.ip_address,
        "status": status,
        "last_seen": aware(item.last_seen),
        "metadata": item.extra,
        "created_at": item.created_at,
    }
