"""One monitoring task per probe, with every capture segment hanging under it.

A probe capturing continuously produces a 30 s segment forever; a task row per
segment buries every other task in the console and says nothing about the thing
an operator actually cares about ("is this probe's monitoring healthy?").
Segments are therefore child work: one long-lived ``monitoring`` task per probe
owns them and carries their counts, while the segments stay individually
addressable through ``payload['monitor_task_id']``.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Task

MONITOR_KIND = "monitoring"
SEGMENT_KIND = "pcap"
CHILD_KEY = "monitor_task_id"


def ensure_monitor_task(db: Session, probe_id: int | None) -> Task | None:
    """The running monitor task for this probe, created on its first capture."""
    if not probe_id:
        return None
    task = db.scalar(
        select(Task)
        .where(Task.kind == MONITOR_KIND, Task.status == "Running",
               Task.payload["probe_id"].as_integer() == int(probe_id))
        .order_by(Task.id.desc()))
    if task is None:
        task = Task(kind=MONITOR_KIND, status="Running", progress=100,
                    current_stage="持续监测中",
                    payload={"probe_id": int(probe_id)})
        db.add(task)
        db.flush()
    return task


def attach_segment(db: Session, monitor: Task, segment: Task) -> None:
    """Point one capture segment at its monitor and refresh the monitor's counts."""
    segment.payload = {**(segment.payload or {}), CHILD_KEY: monitor.id}
    db.flush()
    refresh(db, monitor)


def refresh(db: Session, monitor: Task) -> None:
    """Recompute the monitor's counters from its segments (never stored as truth)."""
    rows = db.scalars(
        select(Task)
        .where(Task.kind == SEGMENT_KIND,
               Task.payload[CHILD_KEY].as_integer() == monitor.id)).all()
    running = sum(1 for row in rows if row.status in ("Pending", "Running"))
    failed = sum(1 for row in rows if row.status in ("Failed", "Partial"))
    analysed = len(rows) - running - failed
    monitor.current_stage = (
        f"持续监测中 · 共 {len(rows)} 段（已分析 {analysed}，进行中 {running}，失败 {failed}）")
    monitor.result = {"segments": len(rows), "analysed": analysed,
                      "running": running, "failed": failed}
