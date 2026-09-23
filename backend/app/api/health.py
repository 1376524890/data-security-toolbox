# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Platform health: the single readiness read the console and operators poll.

Aggregates the API/DB/Redis dependency chain, the Celery queue depth, the worker
capability heartbeat (``api/runtime_status.py``, shared with ``/integrations``),
the probe status histogram, the recording-engine availability, the engine rule
counts and the storage usage.  Nothing here recomputes what a service already
owns; the module owns paths and response shapes only.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.probe_presenter import serialize_probe
from app.api.runtime_status import engine_rule_counts, merge_capability, read_worker_capabilities
from app.core.config import settings
from app.core.database import get_db
from app.models import Probe, Task
from app.services import storage_guard
from app.services.task_dispatch import queue_depth

router = APIRouter()

#: Walking the capture store stat()s ~150k files (seconds of I/O), and the
#: console polls this endpoint from every open tab. The size is telemetry, not a
#: number anyone acts on second-by-second, so it is memoised for a short window
#: instead of re-walked on every poll. The lock keeps a cold burst of polls from
#: each starting the same walk.
_STORAGE_TTL_SECONDS = 30
_storage_lock = threading.Lock()
_storage_cache: tuple[float, int] = (0.0, 0)


def _storage_usage_bytes() -> int:
    global _storage_cache
    stamp, size = _storage_cache
    now = time.monotonic()
    if stamp and now - stamp < _STORAGE_TTL_SECONDS:
        return size
    with _storage_lock:
        stamp, size = _storage_cache
        now = time.monotonic()
        if stamp and now - stamp < _STORAGE_TTL_SECONDS:
            return size
        size = storage_guard.dir_bytes(settings.storage_dir)
        _storage_cache = (now, size)
    return size


def _storage_report(used_bytes: int) -> dict[str, Any]:
    """Storage telemetry that includes the *backing partition*, not just our files.

    ``storage_usage_bytes`` alone answers "how much have we stored", which was
    the only question the console could ask - and it said nothing about how close
    the disk was to full. The platform's data is a bind mount, so its partition
    is usually not ``/``; reporting the partition's own free space is what makes
    the difference between "we hold 39 GB" and "the disk holding those 39 GB has
    19 GB left".
    """
    verdict = storage_guard.pressure()
    return {
        "used_bytes": used_bytes,
        "limit_bytes": verdict["limit_bytes"],
        "path": verdict["path"],
        "partition_total_bytes": verdict["total_bytes"],
        "partition_used_bytes": verdict["used_bytes"],
        "partition_free_bytes": verdict["free_bytes"],
        "partition_used_percent": verdict["used_percent"],
        "floor_bytes": verdict["floor_bytes"],
        "state": verdict["state"],
        "ingest_blocked": verdict["state"] == "critical",
    }


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, Any]:
    # --- everything that needs the pooled connection, and nothing else -------
    oldest = db.scalar(
        select(func.min(Task.created_at)).where(Task.status.in_(["Pending", "Running"]))
    )
    if oldest and oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=UTC)
    probes = db.scalars(select(Probe)).all()
    probe_statuses = {item: 0 for item in ("online", "degraded", "offline", "auth_error")}
    for probe in probes:
        status = serialize_probe(probe)["status"]
        probe_statuses[status] = probe_statuses.get(status, 0) + 1
    probe_count = len(probes)
    pending = db.scalar(select(func.count(Task.id)).where(Task.status == "Pending")) or 0
    # The rest of this endpoint is slow but needs no database: a Celery
    # control-bus ping (~2s) and a size walk over the capture store, which is
    # ~150k files and seconds of I/O. Every open console tab polls this path, and
    # holding a pooled connection across that work drained the pool - once it was
    # empty the auth middleware could not check a session either, so the whole
    # console answered 401 and looked frozen. Release the connection first.
    db.close()

    redis_ok = False
    try:
        import redis as redis_lib

        redis_ok = bool(
            redis_lib.Redis.from_url(
                settings.redis_url, socket_connect_timeout=1, socket_timeout=1
            ).ping()
        )
    except Exception:
        redis_ok = False
    try:
        running, queued, workers = queue_depth()
    except Exception:
        running = 0
        queued = 0
        workers = 0
    oldest_age = max(0.0, (datetime.now(UTC) - oldest).total_seconds()) if oldest else 0.0
    storage_bytes = _storage_usage_bytes()
    capabilities = read_worker_capabilities()
    # A worker is online only if its Redis capability heartbeat is fresh.
    analysis_worker = "online" if capabilities else "offline"
    if capabilities and any(
        item["tshark"].get("available")
        for item in capabilities
        if isinstance(item.get("tshark"), dict)
    ):
        analysis_worker = "ready"
    merged = merge_capability(capabilities)
    # Overall status reflects the core API/DB/Redis dependency chain. Analysis
    # worker capability is reported granularly and separately below.
    status = "ok" if redis_ok else "degraded"
    return {
        "status": status,
        "service": settings.app_name,
        "api": "ok",
        "database": "ok",
        "redis": "ok" if redis_ok else "unavailable",
        "celery": {
            "broker": "ok" if redis_ok else "unavailable",
            "workers": workers,
            "running": running,
            "queued": queued,
        },
        "analysis_worker": analysis_worker,
        "worker_capabilities": capabilities,
        "tshark": merged.get("tshark", {"available": False, "version": ""}),
        "zeek": merged.get("zeek", {"available": False, "version": ""}),
        "suricata": merged.get("suricata", {"available": False, "version": "", "rule_count": 0}),
        "engine_rule_counts": engine_rule_counts(),
        "storage_usage_bytes": storage_bytes,
        "storage_max_bytes": settings.pcap_storage_max_gb * 1024 * 1024 * 1024,
        "storage": _storage_report(storage_bytes),
        "queue": {
            "pending": pending,
            "running": running,
            "oldest_pending_age": oldest_age,
        },
        "probe": {"count": probe_count, **probe_statuses},
        # Capabilities the console must honour rather than probe for itself.
        "features": {"test_data_import": settings.test_data_import_enabled},
    }
