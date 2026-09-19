"""Port through which the API and application layers queue Celery work.

Callers pass a registered task *name* instead of a decorated task object, so
business code never depends on Celery registration. The broker hop is a normal
``send_task``; when the broker is unreachable the task runs in this process,
which is the behaviour a half-configured stack already relied on.
"""

from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.workers.celery_app import celery_app
from app.workers.task_names import (  # noqa: F401  re-exported for dispatch callers
    ANALYZE_ASSETS,
    ANALYZE_METADATA,
    ANALYZE_PCAP,
    DELIVER_ALERT,
    EXPIRE_PROBE_TASKS,
    NETWORK_SCAN,
    RUN_PROBE_DEPLOYMENT,
    SYNC_INTELLIGENCE,
    SYNC_WAZUH_ALERTS,
    WORKER_CAPABILITY_HEARTBEAT,
)

#: Modules whose import registers the task names. Imported lazily so importing
#: this port costs nothing until something is actually dispatched.
_TASK_MODULES = (
    "app.workers.analysis_tasks",
    "app.workers.deployment_tasks",
    "app.workers.maintenance_tasks",
    "app.workers.notification_tasks",
)


def _task(task_name: str):
    import importlib

    for module in _TASK_MODULES:
        importlib.import_module(module)
    try:
        return celery_app.tasks[task_name]
    except KeyError as exc:  # pragma: no cover - misconfiguration, not a path
        raise LookupError(f"Celery task {task_name!r} is not registered") from exc


def dispatch(task_name: str, *args: Any) -> Any:
    """Run ``task_name`` on the queue, falling back to this process."""
    if settings.app_env == "development":
        return _task(task_name)(*args)
    try:
        celery_app.send_task(task_name, args=list(args))
    except Exception:
        return _task(task_name)(*args)
    return None


def dispatch_task_row(task_name: str, task_id: int, *args: Any) -> Any:
    """Dispatch using the platform convention of ``task_id`` as the last arg."""
    return dispatch(task_name, *args, task_id)


def enqueue(task_name: str, *args: Any) -> None:
    """Queue only: raise when the broker rejects the publish.

    Used where the caller must report a 503 instead of running the work inside
    the request (intelligence sync), so there is deliberately no inline fallback.
    """
    celery_app.send_task(task_name, args=list(args))


def dispatch_probe_deployment(deployment_id: int) -> None:
    """Queue a probe deployment/removal through the deployment worker.

    The worker module owns the thread fallback a half-configured stack needs;
    this forwards to it so the API routes never import the worker themselves.
    """
    from app.workers.deployment_tasks import dispatch_probe_deployment as _dispatch

    _dispatch(deployment_id)


def queue_depth(timeout: float = 1) -> tuple[int, int, int]:
    """``(running, queued, workers)`` as reported by the Celery control bus."""
    inspect = celery_app.control.inspect(timeout=timeout)
    active = inspect.active() or {}
    pending = inspect.reserved() or {}
    running = sum(len(items) for items in active.values() if items)
    queued = sum(len(items) for items in pending.values() if items)
    workers = sum(1 for items in active.values() if items is not None)
    return running, queued, workers
