"""Free-space protection for the partition the platform's own data lives on.

The platform's storage is the one producer that can fill its own disk: a probe in
monitoring mode uploads segments faster than they can be analysed, and nothing
used to bound the result. ``PCAP_STORAGE_MAX_GB`` was only *displayed* by
``/health`` - no code path enforced it - and the retention sweep only looked at
age, so a fast producer could fill the partition (taking Postgres and the whole
console down with it) long before the first sweep ran.

Two independent limits are enforced from here, and both are measured on the
partition that really backs ``STORAGE_DIR``. That matters: the platform's data
is a bind mount, so it usually lives on a *different* filesystem than ``/``, and
a percentage of the wrong disk is worse than no number at all.

- a **hard cap** on how much the data partition may hold
  (``PCAP_STORAGE_MAX_GB``), enforced by evicting the oldest segments;
- a **free-space floor** (``PCAP_STORAGE_MIN_FREE_GB`` /
  ``PCAP_STORAGE_MIN_FREE_PERCENT``) below which new uploads are refused, so the
  platform stops taking data in *before* the disk is full instead of after.

Nothing here deletes a row: eviction drops the *file* and leaves the record, so
analysis results, findings and alerts stay attributable to the segment they came
from.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from app.core.config import settings

#: Refusing an upload is a safety valve, not a permanent state: the caller is
#: told when to come back instead of retrying in a tight loop.
RETRY_AFTER_SECONDS = 60


def _existing_ancestor(path: Path) -> Path:
    """The nearest directory that exists; ``statvfs`` needs a real path.

    ``STORAGE_DIR`` is created only by ``settings.ensure_dirs()``, so a health
    check that runs earlier (or a container whose volume is not mounted yet)
    would otherwise raise instead of reporting the backing filesystem.
    """
    candidate = Path(path)
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def partition_usage(path: Path | str | None = None) -> dict[str, Any]:
    """Real usage of the filesystem behind ``path`` (default: the storage dir)."""
    target = _existing_ancestor(Path(path or settings.storage_dir))
    usage = shutil.disk_usage(target)
    total = int(usage.total)
    free = int(usage.free)
    used = int(usage.used)
    percent = round(used * 100.0 / total, 2) if total else 0.0
    return {
        "path": str(target),
        "total_bytes": total,
        "used_bytes": used,
        "free_bytes": free,
        "used_percent": percent,
        "free_percent": round(100.0 - percent, 2) if total else 0.0,
    }


def floor_bytes(total_bytes: int) -> int:
    """The larger of the two floors, so neither setting can be silently ignored."""
    absolute = max(0, int(settings.pcap_storage_min_free_gb)) * 1024 ** 3
    percent = total_bytes * max(0.0, float(settings.pcap_storage_min_free_percent)) / 100.0
    return int(max(absolute, percent))


def pressure(usage: dict[str, Any] | None = None) -> dict[str, Any]:
    """Free-space verdict for the data partition.

    ``critical`` is the only state that stops ingest; ``warning`` exists so the
    console can show the trend before anything is refused.
    """
    usage = usage or partition_usage()
    required = floor_bytes(usage["total_bytes"])
    headroom = int(settings.pcap_storage_warning_free_multiplier * required)
    free = usage["free_bytes"]
    state = "critical" if free < required else "warning" if free < headroom else "ok"
    return {
        **usage,
        "floor_bytes": required,
        "warning_bytes": headroom,
        "state": state,
        "limit_bytes": int(settings.pcap_storage_max_gb) * 1024 ** 3,
    }


def ingest_blocked(verdict: dict[str, Any] | None = None) -> str | None:
    """The reason ingest must stop, or ``None`` when it may continue."""
    verdict = verdict or pressure()
    if verdict["state"] != "critical":
        return None
    return (
        f"数据分区 {verdict['path']} 剩余 {verdict['free_bytes'] // 1024 ** 2} MB，"
        f"低于保留下限 {verdict['floor_bytes'] // 1024 ** 2} MB，已暂停接收抓包"
    )


def dir_bytes(path: Path | str) -> int:
    """Total file size under ``path``; 0 when it does not exist.

    ``os.scandir`` is used rather than ``rglob`` because the storage tree is
    flat and deep at once (thousands of segments), and this runs on a schedule.
    """
    root = Path(path)
    if not root.exists():
        return 0
    total = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat().st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total
