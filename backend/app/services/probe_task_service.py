"""Lifecycle of commands executed by remote probes."""

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import PolicyGroup, Probe, Task

PROBE_TASK_KINDS = ("probe_scan", "data_asset_scan")
TERMINAL = ("Success", "Failed", "Partial", "Cancelled")

#: The kinds a 采集 run creates. They share one list so the task centre's
#: ``kind=collection`` filter and the cockpit's "近 7 天采集任务" row count the
#: same work.
COLLECTION_TASK_KINDS = ("data_asset_scan", "database_scan", "file_source_scan")


def visible_tasks():
    return Task.payload["deleted"].as_boolean().is_not(True)


def default_task_filter():
    """The rows a task list shows unless the caller filters by kind.

    A capture segment is child work of a monitoring task, so the default list
    shows the monitor; ``kind=pcap`` reaches the segments. Shared by
    ``GET /tasks`` and the cockpit's 最近任务 card so both hide the same rows.
    """
    return Task.payload["monitor_task_id"].as_integer().is_(None)


def _validated_policy_group_ids(db: Session, ids: list[int] | None) -> list[int]:
    """The detection items a task should enforce; unknown ids are rejected.

    The ids are recorded on the task so the group's delete guard can see that a
    pending job still depends on it, and so a completed job says which policy it
    was dispatched under.
    """
    cleaned: list[int] = []
    for value in ids or []:
        try:
            group_id = int(value)
        except (TypeError, ValueError):
            continue
        if group_id not in cleaned:
            cleaned.append(group_id)
    if cleaned:
        known = set(db.scalars(select(PolicyGroup.id).where(PolicyGroup.id.in_(cleaned))).all())
        missing = [group_id for group_id in cleaned if group_id not in known]
        if missing:
            raise ProbeTaskNotFound(
                f"策略组不存在: {', '.join(str(item) for item in missing)}")
    return cleaned


def expire_probe_tasks(db):
    now = datetime.now(UTC)
    tasks = db.scalars(
        select(Task)
        .where(
            Task.kind.in_(PROBE_TASK_KINDS),
            Task.status.in_(["Pending", "Running"]),
        )
        .with_for_update()
    ).all()
    for task in tasks:
        origin = (
            task.created_at if task.status == "Pending" else (task.started_at or task.updated_at)
        )
        origin = origin.replace(tzinfo=UTC) if origin.tzinfo is None else origin
        seconds = (
            900
            if task.status == "Pending"
            else int((task.payload.get("config") or {}).get("timeout_seconds", 120)) + 120
        )
        if now - origin > timedelta(seconds=seconds):
            task.error = (
                "探针领取超时，请检查探针版本、远程任务开关和连接状态"
                if task.status == "Pending"
                else "探针执行或回传超时"
            )
            task.status, task.current_stage, task.finished_at = "Failed", task.error, now
    db.flush()


class ProbeTaskNotFound(ValueError):
    """The requested probe no longer exists."""


class ProbeTaskConflict(ValueError):
    """Probe capability or an active job prevents creating another job."""


def queue_probe_scan(db: Session, probe_id: int, config: dict) -> Task:
    """Queue one bounded scan job for a probe (shared by the admin and scan APIs)."""
    expire_probe_tasks(db)
    active = db.scalar(
        select(Task).where(
            Task.kind == "probe_scan",
            Task.payload["probe_id"].as_integer() == probe_id,
            Task.status.in_(["Pending", "Running"]),
        )
    )
    if active:
        raise ProbeTaskConflict("Probe already has an active scan job")
    task = Task(
        kind="probe_scan",
        status="Pending",
        progress=0,
        current_stage="等待探针领取",
        payload={"probe_id": probe_id, "config": config},
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def queue_probe_data_asset_job(db: Session, probe_id: int, config: dict, *, profile=None,
                               policy_group_ids: list[int] | None = None) -> Task:
    """Queue one bounded data-asset job, optionally from a versioned ScanProfile.

    The resolved configuration is copied into the task payload. That copy is the
    authoritative scope: editing the profile afterwards cannot change what a probe
    was already asked to do.
    """
    group_ids = _validated_policy_group_ids(db, policy_group_ids)
    probe = db.get(Probe, probe_id)
    if not probe:
        raise ProbeTaskNotFound("probe not found")
    version = str(
        (probe.extra or {}).get("agent_version") or (probe.extra or {}).get("version") or ""
    )
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if match and tuple(map(int, match.groups())) < (3, 3, 0):
        from app.core.config import settings

        raise ProbeTaskConflict(
            f"探针版本 {version} 不支持数据资产采集，请在探针部署页升级到 "
            f"{settings.probe_agent_version}"
        )
    expire_probe_tasks(db)
    active = db.scalar(
        select(Task).where(
            Task.kind == "data_asset_scan",
            Task.payload["probe_id"].as_integer() == probe_id,
            Task.status.in_(["Pending", "Running"]),
        )
    )
    if active:
        raise ProbeTaskConflict("Probe already has an active data asset job")
    task_payload: dict = {"probe_id": probe_id, "config": config,
                          "policy_group_ids": group_ids}
    if profile is not None:
        # profile_id stays a top-level key so it is queryable for the reference guard.
        task_payload["profile_id"] = profile.id
        task_payload["profile_snapshot"] = {
            "profile_id": profile.id,
            "profile_name": profile.name,
            "profile_version": profile.version,
            "config": config,
        }
    task = Task(
        kind="data_asset_scan",
        status="Pending",
        progress=0,
        current_stage="等待探针领取",
        payload=task_payload,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task
