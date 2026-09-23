"""Shared Probe-row serialisation used by more than one route domain."""

from __future__ import annotations

from typing import Any

from app.core.datetimes import aware
from app.models import Probe
from app.services import probe_status


def serialize_probe(item: Probe) -> dict[str, Any]:
    """One probe row, with its status decided by :mod:`services.probe_status`.

    ``status`` is derived rather than echoed: the stored column can lag a dying
    probe by one beat, and the console must not show a dead host as online just
    because the sweep has not run yet.
    """
    return {
        "id": item.id,
        "name": item.name,
        "hostname": item.hostname,
        "ip_address": item.ip_address,
        "status": probe_status.derive(item),
        "last_seen": aware(item.last_seen),
        "metadata": item.extra,
        "created_at": item.created_at,
    }
