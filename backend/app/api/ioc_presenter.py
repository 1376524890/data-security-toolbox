"""Shared IOC-row serialisation used by more than one route domain."""

from __future__ import annotations

from typing import Any

from app.core.datetimes import aware
from app.models import IOC


def serialize_ioc(item: IOC) -> dict[str, Any]:
    return {
        "id": item.id,
        "type": item.ioc_type,
        "value": item.value,
        "source": item.source,
        "first_seen": item.first_seen,
        "last_seen": aware(item.last_seen),
        "tags": item.tags,
        "metadata": item.extra,
        "created_at": item.created_at,
    }
