"""Task-row persistence shared by the API, application and worker layers.

Creating a task row and updating its progress are database concerns; keeping
them here means HTTP handlers no longer import a Celery worker module (and
therefore the whole analysis stack) just to open a task.
"""

from __future__ import annotations

from typing import Any

from app.core.database import SessionLocal
from app.models import Task


def update_task(task_id: int, **kwargs: Any) -> None:
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        if not task:
            return
        for key, value in kwargs.items():
            setattr(task, key, value)
        if "log" in kwargs and isinstance(kwargs["log"], str):
            task.log = (task.log or "") + kwargs["log"]
        db.commit()


def create_task(db, kind: str, payload: dict[str, Any]) -> Task:
    task = Task(kind=kind, payload=payload)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task
