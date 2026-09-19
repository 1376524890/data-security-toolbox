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

from app.api.pagination import page_response, paginate
from app.api.task_presenter import serialize_task
from app.core.database import get_db
from app.core.security import require_active_admin
from app.models import Task
from app.schemas import TaskCreate
from app.services.probe_task_service import (
    PROBE_TASK_KINDS,
    TERMINAL,
    expire_probe_tasks,
    visible_tasks,
)
from app.services.task_service import create_task

router = APIRouter()


@router.get("/tasks")
def list_tasks(
    status: str | None = None,
    kind: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    expire_probe_tasks(db)
    db.commit()
    query = select(Task).where(visible_tasks())
    if status:
        query = query.where(Task.status == status)
    if kind:
        query = query.where(Task.kind == kind)
    if search:
        query = query.where(
            or_(
                Task.kind.ilike(f"%{search}%"),
                Task.current_stage.ilike(f"%{search}%"),
                Task.error.ilike(f"%{search}%"),
            )
        )
    result = paginate(db, query.order_by(Task.id.desc()), page, page_size)
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
    if task.kind not in PROBE_TASK_KINDS:
        raise HTTPException(409, "当前仅支持停止探针扫描和数据资产采集任务")
    if task.status not in TERMINAL:
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
