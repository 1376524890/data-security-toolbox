"""Shared Task-row serialisation used by more than one route domain."""

from __future__ import annotations

from typing import Any

from app.models import Task
from app.services.data_objects.progress import collection_outcome


def serialize_task(task: Task) -> dict[str, Any]:
    stage, error = task.current_stage, task.error
    if task.kind == "data_asset_scan":
        outcome_stage, error = collection_outcome(task.status, task.result or {}, error)
        stage = outcome_stage or stage
    return {
        "id": task.id,
        "kind": task.kind,
        "status": task.status,
        "progress": task.progress,
        "current_stage": stage,
        "log": task.log,
        "payload": task.payload,
        "result": task.result,
        "worker": (task.result or {}).get("worker", ""),
        "error": error,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "finished_at": task.finished_at,
    }
