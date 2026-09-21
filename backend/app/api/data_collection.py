# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""data collection responsibilities."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.data_collection_schemas import DataAssetProgress as DataAssetProgress
from app.api.data_collection_schemas import DataAssetReport as DataAssetReport
from app.api.data_collection_schemas import DataAssetScanConfig as DataAssetScanConfig
from app.api.dependencies import authenticated_probe as authenticated_probe
from app.core.database import get_db
from app.models import AnalysisResult, Probe, Task
from app.services.data_objects import ingestion, values
from app.services.data_objects.progress import collection_outcome
from app.services.data_objects.progress import progress_percent as progress_percent
from app.services.data_objects.progress import progress_stage as progress_stage
from app.services.probe_task_service import TERMINAL
from app.services.probe_task_service import queue_probe_data_asset_job as queue_probe_data_asset_job
from app.services.report_guard import validate_report

router = APIRouter()


@router.post("/probes/{probe_id}/data-assets/jobs")
def queue_data_asset_scan(
    probe_id: int, payload: DataAssetScanConfig, db: Session = Depends(get_db)
):
    """Queue a bounded data-asset collection for one probe.

    Accepts either an explicit ``paths``/``config`` body (the pre-3.4 contract) or a
    ``profile_id`` reference, which is resolved into the same payload shape.
    """
    from app.services import scan_profile_service

    profile = None
    if payload.profile_id:
        try:
            profile = scan_profile_service.get_or_404(db, payload.profile_id)
        except scan_profile_service.ScanProfileError as exc:
            raise HTTPException(404, str(exc)) from exc
        config = scan_profile_service.probe_config(scan_profile_service.snapshot(profile))
        # An explicit paths list still wins, so the old callers keep working.
        if payload.paths:
            config["paths"] = payload.paths
        if payload.exclude_paths:
            config["exclude_paths"] = payload.exclude_paths
        if payload.file_types:
            config["file_types"] = payload.file_types
        if payload.max_files != DataAssetScanConfig.model_fields["max_files"].default:
            config["max_files"] = payload.max_files
        if payload.max_depth != DataAssetScanConfig.model_fields["max_depth"].default:
            config["max_depth"] = payload.max_depth
        if payload.timeout_seconds != DataAssetScanConfig.model_fields["timeout_seconds"].default:
            config["timeout_seconds"] = payload.timeout_seconds
        if not config.get("paths"):
            raise HTTPException(400, "扫描配置未设置 include_paths，探针没有可扫描的目录")
    else:
        config = payload.model_dump(exclude={"profile_id"})
    task = queue_probe_data_asset_job(db, probe_id, config, profile=profile)
    return {"id": task.id, "status": task.status, "location": "probe"}


@router.post("/probes/{probe_id}/data-assets")
def data_asset_inventory(
    probe_id: int, payload: DataAssetReport, request: Request, db: Session = Depends(get_db)
):
    """Ingest a probe-side data asset inventory (idempotent per report).

    One transaction writes the object/instance/detection model *and* its derived
    ``data_assets`` projection, so the legacy pages and the new query APIs can
    never disagree. A report for a task that already reached a terminal state is
    acknowledged without applying anything: a late re-send must not roll the
    current view back.
    """
    probe = authenticated_probe(probe_id, request, db)
    # Independent check of the probe's own guard. Violations are reported as codes
    # only - echoing the offending value back would defeat the purpose.
    body = payload.model_dump()
    violations = validate_report(body)
    if violations:
        raise HTTPException(
            422,
            detail={
                "error": "unsafe_report",
                "violations": [item.to_dict() for item in violations],
            },
        )
    db.execute(select(Probe.id).where(Probe.id == probe_id).with_for_update())
    task = (
        db.scalar(select(Task).where(Task.id == payload.task_id).with_for_update())
        if payload.task_id
        else db.scalar(
            select(Task).where(
                Task.kind == "data_asset_scan",
                Task.payload["probe_id"].as_integer() == probe_id,
                Task.payload["report_id"].as_string() == payload.report_id,
            )
        )
    )
    if payload.task_id and (
        not task or task.kind != "data_asset_scan" or task.payload.get("probe_id") != probe_id
    ):
        raise HTTPException(403, "data asset task does not belong to probe")
    if task and (task.status in TERMINAL or task.payload.get("deleted")):
        return {"id": task.id, "duplicate": True, "assets": task.result.get("assets", 0)}
    if not task:
        task = Task(
            kind="data_asset_scan", payload={"probe_id": probe_id, "report_id": payload.report_id}
        )
        db.add(task)
        db.flush()
    now = datetime.now(UTC)
    outcome = ingestion.ingest_report(db, probe, body, task)
    stored = outcome["stored"]
    task.status = "Failed" if payload.error else ("Success" if payload.complete else "Partial")
    task.progress, task.current_stage, task.finished_at = 100, "探针数据资产采集完成", now
    task.error = payload.error
    task.result = {
        "assets": stored,
        "asset_instance_ids": outcome["asset_instance_ids"],
        "complete": payload.complete,
        "report_id": payload.report_id,
        "location": "probe",
        "paths": payload.scanned_paths,
        "databases": len(payload.databases),
        "host": probe.ip_address or probe.hostname,
        "scan_id": outcome["scan_id"],
        "schema_version": values.detect_report_schema(body),
        "complete_scope": outcome["complete_scope"],
        "not_observed": outcome["not_observed"],
        "stale_entries": outcome["late_skipped"],
        "ruleset_version": payload.ruleset_version,
        "engine_version": payload.engine_version,
        "profile_version": payload.profile_version,
        "coverage": payload.coverage,
        "budget": payload.budget,
    }
    task.current_stage, task.error = collection_outcome(task.status, task.result, task.error)
    probe.extra = {
        **(probe.extra or {}),
        "last_data_asset_scan": {**task.result, "status": task.status, "at": now.isoformat()},
    }
    probe.last_seen = now
    db.add(
        AnalysisResult(
            task_id=task.id,
            module="data_assets",
            content=task.result,
            risk_level="High"
            if any(
                item.sensitivity in ("Critical", "High")
                for item in [*payload.assets, *payload.databases]
            )
            else "Low",
        )
    )
    db.commit()
    return {
        "id": task.id,
        "duplicate": False,
        "assets": stored,
        "scan_id": outcome["scan_id"],
        "complete_scope": outcome["complete_scope"],
        "not_observed": outcome["not_observed"],
        # Entries dropped because a newer scan had already been applied.
        "stale": outcome["late_skipped"],
    }


@router.post("/probes/{probe_id}/data-assets/progress")
def data_asset_progress(
    probe_id: int, payload: DataAssetProgress, request: Request, db: Session = Depends(get_db)
):
    """Record progress on a running task, at whatever rate the probe chose.

    Deliberately narrow: progress cannot set a task's status, cannot clear its
    error and cannot resurrect a finished task. That is what keeps a stalled
    probe from freezing the task lifecycle, and a failed progress push from
    failing the scan.
    """
    authenticated_probe(probe_id, request, db)
    task = db.get(Task, payload.task_id)
    if (
        not task
        or task.kind != "data_asset_scan"
        or (task.payload or {}).get("probe_id") != probe_id
    ):
        raise HTTPException(404, "data asset task not found")
    if task.status in TERMINAL or (task.payload or {}).get("deleted"):
        return {"id": task.id, "status": task.status, "applied": False}
    coverage = payload.coverage if isinstance(payload.coverage, dict) else {}
    estimated = progress_percent(coverage)
    task.progress = estimated["percent"]
    task.current_stage = progress_stage(coverage, payload.current_path)
    task.payload = {
        **(task.payload or {}),
        "progress": {
            **{
                key: coverage.get(key)
                for key in (
                    "max_files",
                    "files_discovered",
                    "files_analyzed",
                    "files_skipped",
                    "directories_scanned",
                    "bytes_read",
                    "sensitive_assets",
                    "detections",
                    "elapsed_seconds",
                    "termination_reason",
                )
            },
            "current_path": payload.current_path,
            "scan_id": payload.scan_id,
            "percent": estimated["percent"],
            "estimated": estimated["estimated"],
            "basis": estimated["basis"],
            "reported_at": datetime.now(UTC).isoformat(),
        },
    }
    db.commit()
    return {"id": task.id, "status": task.status, "applied": True}
