"""Shared Task-row serialisation used by more than one route domain."""

from __future__ import annotations

from typing import Any

from app.models import Task


def serialize_task(task: Task) -> dict[str, Any]:
    return {
        "id": task.id,
        "kind": task.kind,
        "status": task.status,
        "progress": task.progress,
        "current_stage": task.current_stage,
        "log": task.log,
        "payload": task.payload,
        "result": task.result,
        "worker": (task.result or {}).get("worker", ""),
        "error": task.error,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "finished_at": task.finished_at,
    }
