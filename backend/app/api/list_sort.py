"""Whitelisted ``order_by`` handling shared by the paginated list endpoints.

One convention across the console: ``order_by=field`` sorts ascending and
``order_by=-field`` descending. A key outside the endpoint's whitelist is
rejected with 400 instead of being ignored - silently falling back to the
default order is how a page ends up showing a sort it never applied.

The whitelist is also the safety boundary: only a column the endpoint names can
become an ``ORDER BY``, so a query parameter can never turn into an unindexed
full scan.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from fastapi import HTTPException


def resolve_order(order_by: str | None, sortable: Mapping[str, Any], *,
                  default: str) -> tuple[str, bool]:
    """``(key, descending)`` for ``order_by``; ``default`` when it is empty."""
    raw = str(order_by or "").strip()
    key = raw.lstrip("-") or default
    if key not in sortable:
        raise HTTPException(400, detail={"error": "unsupported_sort",
                                         "allowed": sorted(sortable)})
    return key, raw.startswith("-")


def order_query(query: Any, order_by: str | None, sortable: Mapping[str, Any], *,
                default: str, default_desc: bool = False) -> Any:
    """Apply the resolved sort to a SQLAlchemy ``select()``.

    ``default_desc`` keeps an endpoint's natural "newest first" order when the
    caller passes nothing, so adding a sort knob never reorders an existing page.
    """
    if not order_by:
        column = sortable[default]
        return query.order_by(column.desc() if default_desc else column.asc())
    key, descending = resolve_order(order_by, sortable, default=default)
    column = sortable[key]
    return query.order_by(column.desc() if descending else column.asc())


def order_rows(rows: list[Any], order_by: str | None, keys: Mapping[str, Callable[[Any], Any]], *,
               default: str, default_desc: bool = False) -> list[Any]:
    """Sort an already-built list (an endpoint that merges rows in Python).

    The list's natural order stays the default, so a caller that passes no
    ``order_by`` sees exactly what it saw before this helper existed.
    """
    if not order_by:
        return list(reversed(rows)) if default_desc else list(rows)
    key, descending = resolve_order(order_by, keys, default=default)
    read = keys[key]
    # Rows without a value are split out before reversing: ``reverse=True`` would
    # otherwise carry a null to the top of a descending list, which reads as
    # "highest" rather than "unknown".
    present = [row for row in rows if read(row) is not None]
    missing = [row for row in rows if read(row) is None]
    present.sort(key=lambda row: _sortable(read(row)), reverse=descending)
    return present + missing


def _sortable(value: Any) -> tuple[int, Any]:
    """A total order for a possibly-missing column: ``None`` sorts last.

    The leading rank keeps a mixed column (a number here, ``None`` there) from
    comparing a ``str`` against a ``float``; within one rank the values share a
    type by construction.
    """
    if value is None:
        return (2, 0.0)
    if isinstance(value, (int, float)):
        return (0, float(value))
    return (1, str(value))
