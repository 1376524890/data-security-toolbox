"""Query helpers shared by the list endpoints of more than one domain."""

from __future__ import annotations


def string_time_filter(query, column, start_time: str | None, end_time: str | None):
    if start_time:
        query = query.where(column >= start_time)
    if end_time:
        query = query.where(column <= end_time)
    return query
