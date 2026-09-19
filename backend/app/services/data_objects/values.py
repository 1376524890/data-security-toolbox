"""Report value normalization shared within the data-object domain."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services import sensitivity_map
from app.services.data_objects.definitions import REPORT_SCHEMA_SUPPORTED


def category_name(value: Any) -> str:
    """One stable category name for a type, whatever alias the caller used.

    The platform keeps the existing lowercase names (``phone``, ``id_card``) so
    the legacy pages and the new type centre cannot disagree about what "the same
    type" means; an analyst-authored type with no legacy alias keeps its own name
    in lowercase instead of being dropped.
    """
    canonical = sensitivity_map.engine.canonical_entity(value)
    return (sensitivity_map.engine.legacy_name(canonical) or canonical.lower())[:64]


def _text(value: Any, limit: int) -> str:
    return str(value or "")[:limit]


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; treat them as UTC, never as local time."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _newest(*values: datetime | None) -> datetime | None:
    present = [_aware(value) for value in values if value is not None]
    return max(present) if present else None


def _iso(value: datetime | None) -> str:
    aware = _aware(value)
    return aware.isoformat() if aware else ""


def detect_report_schema(payload: dict[str, Any]) -> str:
    """The schema version a payload claims; anything unknown is treated as 1.0."""
    claimed = _text(payload.get("schema_version"), 16)
    return claimed if claimed in REPORT_SCHEMA_SUPPORTED else "1.0"
