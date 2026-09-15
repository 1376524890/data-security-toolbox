"""Lifecycle of commands executed by remote probes."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models import Task

PROBE_TASK_KINDS = ('probe_scan', 'data_asset_scan')
TERMINAL = ('Success', 'Failed', 'Partial', 'Cancelled')


def visible_tasks():
    return Task.payload['deleted'].as_boolean().is_not(True)


def expire_probe_tasks(db):
    now = datetime.now(UTC)
    tasks = db.scalars(select(Task).where(
        Task.kind.in_(PROBE_TASK_KINDS), Task.status.in_(['Pending', 'Running']),
    ).with_for_update()).all()
    for task in tasks:
        origin = task.created_at if task.status == 'Pending' else (task.started_at or task.updated_at)
        origin = origin.replace(tzinfo=UTC) if origin.tzinfo is None else origin
        seconds = 900 if task.status == 'Pending' else int((task.payload.get('config') or {}).get('timeout_seconds', 120)) + 120
        if now - origin > timedelta(seconds=seconds):
            task.error = '探针领取超时，请检查探针版本、远程任务开关和连接状态' if task.status == 'Pending' else '探针执行或回传超时'
            task.status, task.current_stage, task.finished_at = 'Failed', task.error, now
    db.flush()
