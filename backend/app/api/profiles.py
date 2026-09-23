"""ScanProfile CRUD and profile-driven collection jobs."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.services.probe_task_service import queue_probe_data_asset_job
from app.core.database import get_db
from app.core.security import get_session_user
from app.models import Probe, ScanProfile, Task
from app.services import scan_profile_service
from app.services.scan_profile_service import ScanProfileError

router = APIRouter(prefix="/api/v1", tags=["scan-profiles"])

#: Whitelisted sort keys; anything else is rejected instead of interpolated.
SORTABLE = {"id": ScanProfile.id, "name": ScanProfile.name, "version": ScanProfile.version,
            "updated_at": ScanProfile.updated_at, "created_at": ScanProfile.created_at}


class ProfilePayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    include_paths: list[str] = Field(default_factory=list, max_length=64)
    exclude_paths: list[str] = Field(default_factory=list, max_length=64)
    file_types: list[str] = Field(default_factory=list, max_length=64)
    #: Coverage knobs default to 0 = "no limit", matching the shared budget and
    #: the probe: a profile created without touching them must not silently cap a
    #: scan at 500 directories / depth 3 / 120 s (that is the old bounded design).
    #: The content knobs below keep their shipped values - they bound how much of
    #: one file is parsed, not which files the scan reaches.
    max_files: int = 0
    max_dirs: int = 0
    max_depth: int = 0
    max_runtime_seconds: int = 0
    max_bytes_read: int = 0
    max_single_file_size: int = 0
    max_full_hash_size: int = 0
    large_file_sampling: bool = True
    sample_block_size: int = 64 * 1024
    max_sample_rows: int = 25
    max_cpu_seconds: float = 0.0
    max_rss_mb: float = 0.0
    xlsx_max_entries: int = 512
    xlsx_max_uncompressed_bytes: int = 64 * 1024 * 1024
    xlsx_max_compression_ratio: float = 200.0
    xlsx_max_shared_strings: int = 200_000
    xlsx_max_sheets: int = 32
    xlsx_max_columns: int = 256
    xlsx_max_rows: int = 200
    enabled: bool = True
    scheduled: bool = False
    interval_seconds: int = 3600


class ProfilePatch(BaseModel):
    """Every field optional: a PATCH changes only what it sends."""

    name: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    include_paths: list[str] | None = None
    exclude_paths: list[str] | None = None
    file_types: list[str] | None = None
    max_files: int | None = None
    max_dirs: int | None = None
    max_depth: int | None = None
    max_runtime_seconds: int | None = None
    max_bytes_read: int | None = None
    max_single_file_size: int | None = None
    max_full_hash_size: int | None = None
    large_file_sampling: bool | None = None
    sample_block_size: int | None = None
    max_sample_rows: int | None = None
    max_cpu_seconds: float | None = None
    max_rss_mb: float | None = None
    xlsx_max_entries: int | None = None
    xlsx_max_uncompressed_bytes: int | None = None
    xlsx_max_compression_ratio: float | None = None
    xlsx_max_shared_strings: int | None = None
    xlsx_max_sheets: int | None = None
    xlsx_max_columns: int | None = None
    xlsx_max_rows: int | None = None
    enabled: bool | None = None
    scheduled: bool | None = None
    interval_seconds: int | None = None


class RunPayload(BaseModel):
    probe_id: int


def _actor(db: Session, request: Request) -> str:
    try:
        user = get_session_user(db, request)
    except Exception:
        user = None
    return str(getattr(user, "username", "") or "admin")


@router.get("/scan-profiles")
def list_profiles(enabled: bool | None = Query(default=None),
                  name: str = Query(default="", max_length=128),
                  sort: str = Query(default="id"), order: str = Query(default="desc"),
                  page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                  db: Session = Depends(get_db)) -> dict:
    if sort not in SORTABLE:
        raise HTTPException(400, f"不支持的排序字段: {sort}")
    query = select(ScanProfile)
    if enabled is not None:
        query = query.where(ScanProfile.enabled.is_(enabled))
    if name:
        query = query.where(ScanProfile.name.ilike(f"%{name}%"))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    column = SORTABLE[sort]
    query = query.order_by(column.desc() if order == "desc" else column.asc())
    rows = db.scalars(query.offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [scan_profile_service.serialize(row) for row in rows], "total": total,
            "page": page, "page_size": page_size}


@router.post("/scan-profiles")
def create_profile(payload: ProfilePayload, request: Request, db: Session = Depends(get_db)) -> dict:
    values = payload.model_dump()
    name = values.pop("name")
    try:
        clean = scan_profile_service.validate(values)
    except ScanProfileError as exc:
        raise HTTPException(400, str(exc)) from exc
    existing = db.scalar(select(func.max(ScanProfile.version)).where(ScanProfile.name == name))
    profile = ScanProfile(name=name, version=(existing or 0) + 1,
                          created_by=_actor(db, request), **clean)
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return scan_profile_service.serialize(profile)


@router.get("/scan-profiles/{profile_id}")
def get_profile(profile_id: int, db: Session = Depends(get_db)) -> dict:
    profile = db.get(ScanProfile, profile_id)
    if profile is None:
        raise HTTPException(404, "scan profile not found")
    return scan_profile_service.serialize(profile)


@router.patch("/scan-profiles/{profile_id}")
def update_profile(profile_id: int, payload: ProfilePatch, db: Session = Depends(get_db)) -> dict:
    profile = db.get(ScanProfile, profile_id)
    if profile is None:
        raise HTTPException(404, "scan profile not found")
    supplied = {key: value for key, value in payload.model_dump(exclude_unset=True).items()
                if value is not None}
    if not supplied:
        return scan_profile_service.serialize(profile)
    try:
        clean = scan_profile_service.validate(supplied)
    except ScanProfileError as exc:
        raise HTTPException(400, str(exc)) from exc
    scan_profile_service.apply_values(profile, clean)
    # The revision counter moves so an operator can tell two edits apart; tasks
    # that already ran keep the snapshot they were queued with.
    profile.version = int(profile.version or 1) + 1
    db.commit()
    db.refresh(profile)
    return scan_profile_service.serialize(profile)


@router.delete("/scan-profiles/{profile_id}")
def delete_profile(profile_id: int, db: Session = Depends(get_db)) -> dict:
    profile = db.get(ScanProfile, profile_id)
    if profile is None:
        raise HTTPException(404, "scan profile not found")
    active = db.scalar(select(Task.id).where(
        Task.kind.in_(("data_asset_scan", "probe_scan")),
        Task.payload["profile_id"].as_integer() == profile_id,
        Task.status.in_(("Pending", "Running"))))
    if active:
        raise HTTPException(409, "该配置仍被未完成的任务引用，请先取消任务")
    db.delete(profile)
    db.commit()
    return {"status": "deleted"}


@router.post("/scan-profiles/{profile_id}/run")
def run_profile(profile_id: int, payload: RunPayload, db: Session = Depends(get_db)) -> dict:
    """Queue a collection on one probe using this profile's current settings."""
    profile = db.get(ScanProfile, profile_id)
    if profile is None:
        raise HTTPException(404, "scan profile not found")
    if not profile.enabled:
        raise HTTPException(409, "该扫描配置已停用")
    probe = db.get(Probe, payload.probe_id)
    if probe is None:
        raise HTTPException(404, "probe not found")
    config = scan_profile_service.probe_config(scan_profile_service.snapshot(profile))
    if not config["paths"]:
        raise HTTPException(400, "扫描配置未设置 include_paths，探针没有可扫描的目录")
    try:
        task = queue_probe_data_asset_job(db, payload.probe_id, config, profile=profile)
    except HTTPException:
        raise
    return {"id": task.id, "status": task.status, "location": "probe",
            "profile_id": profile.id, "profile_version": profile.version}
