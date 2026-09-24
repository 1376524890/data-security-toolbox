# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Task queue domain: the console view of platform and probe work.

The HTTP boundary only: the rows are created by ``services/task_service.py``
and expired by ``services/probe_task_service.py``; this module owns the list
filters, the admin-only stop/delete guard and the response shape.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.list_sort import order_query
from app.api.pagination import page_response, paginate
from app.api.task_presenter import serialize_task
from app.core.database import get_db
from app.core.security import require_active_admin
from app.models import Task
from app.schemas import TaskCreate
from app.services import monitoring, probe_lifecycle
from app.services.probe_task_service import (
    COLLECTION_TASK_KINDS,
    PROBE_TASK_KINDS,
    TERMINAL,
    default_task_filter,
    expire_probe_tasks,
    visible_tasks,
)
from app.services.task_service import create_task

#: Tasks the stop endpoint may cancel. Everything listed here observes the
#: Cancelled status somewhere: a probe-instructed job on its next poll (and the
#: probe checks the command status before it reports), a platform-side job in
#: its own worker between units of work, and a monitoring session through its
#: segments. A kind whose executor cannot notice would only look stopped.
STOPPABLE_TASK_KINDS = (
    *PROBE_TASK_KINDS,
    monitoring.MONITOR_KIND,
    monitoring.SEGMENT_KIND,
    "database_scan",
    "file_source_scan",
    "scan",
)

#: Whitelisted sort keys for ``GET /tasks`` (``order_by=-created_at`` etc.).
TASK_SORTABLE = {
    "id": Task.id, "kind": Task.kind, "status": Task.status,
    "progress": Task.progress, "created_at": Task.created_at,
    "started_at": Task.started_at, "finished_at": Task.finished_at,
}

STOP_UNSUPPORTED = (
    "当前仅支持停止探针扫描、数据资产采集、数据库采集、文件源采集、"
    "网络扫描、流量解析和监测任务"
)

router = APIRouter()


@router.get("/tasks")
def list_tasks(
    status: str | None = None,
    kind: str | None = None,
    search: str | None = None,
    order_by: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    expire_probe_tasks(db)
    db.commit()
    query = select(Task).where(visible_tasks())
    if status:
        query = query.where(Task.status == status)
    if kind == "collection":
        query = query.where(Task.kind.in_(COLLECTION_TASK_KINDS))
    elif kind:
        query = query.where(Task.kind == kind)
    else:
        query = query.where(default_task_filter())
    if search:
        query = query.where(
            or_(
                Task.kind.ilike(f"%{search}%"),
                Task.current_stage.ilike(f"%{search}%"),
                Task.error.ilike(f"%{search}%"),
            )
        )
    result = paginate(db, order_query(query, order_by, TASK_SORTABLE,
                                       default="id", default_desc=True), page, page_size)
    for item in result["items"]:
        if item.kind == monitoring.MONITOR_KIND:
            monitoring.refresh(db, item)
    db.commit()
    return page_response(
        [serialize_task(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.post("/tasks")
def create_generic_task(payload: TaskCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, payload.kind, payload.payload)
    return serialize_task(task)


@router.get("/tasks/{task_id}")
def task_detail(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = db.get(Task, task_id)
    if not task or task.payload.get("deleted"):
        raise HTTPException(404, "task not found")
    return serialize_task(task)


@router.post("/tasks/{task_id}/stop", dependencies=[Depends(require_active_admin)])
def stop_task(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = db.scalar(select(Task).where(Task.id == task_id).with_for_update())
    if not task or task.payload.get("deleted"):
        raise HTTPException(404, "任务不存在")
    if task.kind not in STOPPABLE_TASK_KINDS:
        raise HTTPException(409, STOP_UNSUPPORTED)
    if task.status not in TERMINAL:
        if task.kind == monitoring.MONITOR_KIND:
            # A monitoring row owns one task per capture segment, so stopping it
            # has to end those rows too — they are separate queue entries and
            # would otherwise keep the analysis pipeline busy after the operator
            # has said stop. The probe a console 监测任务 installed is
            # task-dedicated, so reaching a terminal state is also what takes it
            # off the host (the retire path queues the uninstall).
            stopped = monitoring.stop_monitor(db, task)
            probe_lifecycle.retire_after_task(db, task)
            task.current_stage = f"已停止监测，同时取消 {stopped} 段待分析流量"
        else:
            task.status, task.current_stage = "Cancelled", "已停止；已领取任务由探针检查后退出"
            task.finished_at = datetime.now(UTC)
        db.commit()
    return serialize_task(task)


@router.delete("/tasks/{task_id}", dependencies=[Depends(require_active_admin)])
def delete_task(task_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    task = db.scalar(select(Task).where(Task.id == task_id).with_for_update())
    if not task or task.payload.get("deleted"):
        raise HTTPException(404, "任务不存在")
    if task.status not in TERMINAL:
        raise HTTPException(409, "请先停止任务，或等待任务完成后再删除")
    # Keep a tombstone for late probe reports and linked analysis evidence.
    task.payload = {**task.payload, "deleted": True}
    db.commit()
    return {"status": "ok"}
