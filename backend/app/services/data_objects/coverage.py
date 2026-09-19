"""Coverage and report ordering decisions."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from app.models import AssetInstance
from app.services.data_objects.values import _aware, _int, _text


def in_scope(path: str, roots: Iterable[str], max_depth: Any, instance_type: str) -> bool:
    """Reproduce the pre-existing scope test so the sweep cannot widen by accident.

    Only absolute paths beneath an actually scanned root count, and the depth
    allowance matches what the walker would have visited.

    Configured exclusions and the type allow-list are deliberately *not* consulted
    here: a path the operator excluded is still inside the scanned tree, so a
    complete run that no longer reports it has genuinely stopped seeing it and must
    retire it. Treating an excluded path as outside the sweep's authority is what
    would freeze it as ACTIVE forever.
    """
    depth = _int(max_depth, -1)
    if depth < 0 or not str(path or "").startswith("/"):
        return False
    allowance = depth + (0 if instance_type == "directory" else 1)
    target = PurePosixPath(path)
    for root in roots:
        if not str(root or "").startswith("/"):
            continue
        try:
            relative = target.relative_to(PurePosixPath(root))
        except ValueError:
            continue
        if len(relative.parts) <= allowance:
            return True
    return False


def complete_scope(payload: dict[str, Any]) -> bool:
    """Whether *this* report covered the whole scope it declared.

    A 1.1 report states it outright. A legacy 3.3.1 report has only ``complete``,
    so it keeps exactly the meaning it always had - that is the compatibility
    branch, not a guess about its coverage metadata.

    ``complete`` defaults to ``True`` in the 3.3.1 schema, so an absent field
    means "the walk finished". Requiring it to be present would silently stop
    sweeping for every old probe: a file that really was deleted would stay
    ``observed`` forever, which is the one outcome this model must not produce.
    """
    stated = payload.get("completed_scope")
    if isinstance(stated, bool):
        return stated
    return bool(payload.get("complete", True)) and not _text(payload.get("error"), 500)


def _is_late(instance: AssetInstance, observed_at: datetime) -> bool:
    """True when a newer report has already been applied to this instance."""
    previous = _aware(instance.last_scan_at)
    if previous is None:
        return False
    return observed_at < previous
