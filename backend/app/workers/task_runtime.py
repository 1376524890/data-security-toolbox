"""Celery-side task lifecycle: status rows, failure capture and the guard.

Kept out of the task modules so every queue entry point reports progress the
same way, and out of the services so domain code never imports Celery helpers.
"""

from __future__ import annotations

import functools
from datetime import UTC, datetime
from typing import Any

from app.services.task_service import update_task


def _finish(
    task_id: int,
    error: str = "",
    result: dict[str, Any] | None = None,
    status: str | None = None,
) -> None:
    import socket as _socket

    payload = dict(result or {})
    payload.setdefault("worker", _socket.gethostname())
    final = status or ("Success" if not error else "Failed")
    stage = {"Success": "done", "Partial": "partial", "Failed": "failed"}.get(final, final.lower())
    update_task(
        task_id,
        status=final,
        progress=100,
        current_stage=stage,
        error=error,
        finished_at=datetime.now(UTC),
        result=payload,
    )


def _mark_failed(task_id: int, exc: Exception, stage: str = "failed") -> None:
    """A task must never remain Running; any exception lands in Failed."""
    import traceback

    update_task(
        task_id,
        status="Failed",
        progress=100,
        current_stage=stage,
        error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[:2000]}",
        finished_at=datetime.now(UTC),
    )


def _mark_running(task_id: int, progress: int, stage: str) -> None:
    update_task(task_id, status="Running", progress=progress, current_stage=stage)


def task_guard(func):
    """Wrap a Celery task so any exception lands the Task row in Failed.

    A task must never remain ``Running``. The guard extracts ``task_id`` from
    the final positional arg or the ``task_id`` kwarg, marks Failed with a full
    stack trace, then re-raises so Celery logs the real failure.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        task_id = kwargs.get("task_id") or (
            args[-1] if args and isinstance(args[-1], int) else None
        )
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            if task_id is not None:
                _mark_failed(int(task_id), exc)
            raise

    return wrapper
