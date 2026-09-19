"""Datetime normalisation shared by the API response presenters.

Database columns hold naive timestamps while transcripts and payloads carry ISO
strings; presenters need one spelling of ``last_seen`` regardless of the writer.
"""

from __future__ import annotations

from datetime import UTC, datetime


def aware(value: datetime | str | None) -> datetime | str | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
