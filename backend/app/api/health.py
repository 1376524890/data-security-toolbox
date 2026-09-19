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
from app.services.task_dispatch import queue_depth

router = APIRouter()


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, Any]:
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
    oldest = db.scalar(
        select(func.min(Task.created_at)).where(Task.status.in_(["Pending", "Running"]))
    )
    if oldest and oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=UTC)
    oldest_age = max(0.0, (datetime.now(UTC) - oldest).total_seconds()) if oldest else 0.0
    storage_bytes = sum(
        path.stat().st_size for path in settings.storage_dir.rglob("*") if path.is_file()
    )
    probes = db.scalars(select(Probe)).all()
    probe_statuses = {item: 0 for item in ("online", "degraded", "offline", "auth_error")}
    for probe in probes:
        probe_statuses[serialize_probe(probe)["status"]] = (
            probe_statuses.get(serialize_probe(probe)["status"], 0) + 1
        )
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
        "queue": {
            "pending": db.scalar(select(func.count(Task.id)).where(Task.status == "Pending")) or 0,
            "running": running,
            "oldest_pending_age": oldest_age,
        },
        "probe": {"count": len(probes), **probe_statuses},
        # Capabilities the console must honour rather than probe for itself.
        "features": {"test_data_import": settings.test_data_import_enabled},
    }
