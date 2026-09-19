# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""File-evidence domain: upload, listing, download and re-analysis.

The HTTP boundary only: ``services/metadata_service.py`` owns hashing and the
worker owns detection. Probe ownership of an upload and Task-row serialisation
are shared with the other upload domains and live in ``app.api.dependencies``
and ``app.api.task_presenter``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.data_assets import _serialize_data_asset as _serialize_data_asset
from app.api.dependencies import upload_probe_id
from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.pagination import page_response, paginate
from app.api.task_presenter import serialize_task
from app.core.config import settings
from app.core.database import get_db
from app.core.storage import stream_to_storage
from app.models import DataAsset, DetectionFinding, FileRecord
from app.services.task_dispatch import ANALYZE_METADATA, dispatch_task_row
from app.services.task_service import create_task

router = APIRouter()


# The console filters files by extension ("png") while the record stores the
# detected MIME ("image/png"). Map both spellings onto one candidate set so a
# filter never silently returns nothing.
FILE_TYPE_ALIASES: dict[str, str] = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "txt": "text/plain",
    "csv": "text/csv",
    "json": "application/json",
    "xml": "application/xml",
    "zip": "application/zip",
    "gz": "application/gzip",
    "unknown": "application/octet-stream",
}


def _file_type_candidates(file_type: str) -> list[str]:
    """Return every stored spelling that matches the requested filter value."""
    value = file_type.strip()
    candidates = {value}
    alias = FILE_TYPE_ALIASES.get(value.lower())
    if alias:
        candidates.add(alias)
    candidates.update(ext for ext, mime in FILE_TYPE_ALIASES.items() if mime == value.lower())
    return sorted(candidates)


def serialize_file(item: FileRecord) -> dict[str, Any]:
    return {
        "id": item.id,
        "probe_id": item.probe_id,
        "name": item.name,
        "path": item.path,
        "size": item.size,
        "sha256": item.sha256,
        "md5": item.md5,
        "file_type": item.file_type,
        "metadata_json": item.metadata_json,
        "risk_level": item.risk_level,
        "created_at": item.created_at,
    }


@router.post("/files/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    probe_id: int | None = Form(None),
    metadata_json: str | None = Form(None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    probe_id = upload_probe_id(request, db, probe_id)
    try:
        stored = await stream_to_storage(
            file,
            file.filename or "upload.bin",
            subdir="uploads",
            max_bytes=settings.max_upload_mb * 1024 * 1024,
        )
    except ValueError as exc:
        if "too_large" in str(exc):
            raise HTTPException(413, "file too large") from exc
        raise
    path = Path(stored["path"])
    try:
        meta = json.loads(metadata_json) if metadata_json else {}
    except (TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(422, "metadata_json must be valid JSON") from exc
    if not isinstance(meta, dict):
        raise HTTPException(422, "metadata_json must be a JSON object")
    # Probe already reports md5/sha256 for target files; fall back to computing
    # the digests from the stored bytes so the hash is always persisted.
    md5 = str(meta.get("md5") or "") if isinstance(meta, dict) else ""
    if not md5:
        from app.services.metadata_service import md5_file

        md5 = md5_file(path)
    record = FileRecord(
        probe_id=probe_id,
        name=path.name,
        path=str(path),
        size=int(stored["size"]),
        sha256=str(stored["sha256"]),
        md5=md5,
        file_type="",
        metadata_json=meta,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    task = create_task(db, "metadata", {"file_id": record.id})
    dispatch_task_row(ANALYZE_METADATA, task.id, record.id)
    return {"id": record.id, "task_id": task.id, "name": record.name, "size": record.size}


@router.get("/files")
def list_files(
    search: str | None = None,
    file_type: str | None = None,
    risk_level: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(FileRecord)
    if search:
        query = query.where(FileRecord.name.ilike(f"%{search}%"))
    if file_type:
        # The console filters by extension ("png") while the record stores the
        # detected MIME ("image/png"); accept both spellings of the same format.
        candidates = _file_type_candidates(file_type)
        query = query.where(FileRecord.file_type.in_(candidates))
    if risk_level:
        query = query.where(FileRecord.risk_level == risk_level)
    result = paginate(db, query.order_by(FileRecord.id.desc()), page, page_size)
    return page_response(
        [serialize_file(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/files/{file_id}")
def file_detail(file_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(FileRecord, file_id)
    if not item:
        raise HTTPException(404, "file not found")
    # Only the latest analysis run is "current". Previous runs are kept for
    # history but must not be counted again here.
    findings = [
        row
        for row in db.scalars(
            select(DetectionFinding)
            .where(
                DetectionFinding.target_type == "file", DetectionFinding.target_id == str(file_id)
            )
            .order_by(DetectionFinding.risk_score.desc())
        ).all()
        if not (row.evidence or {}).get("superseded")
    ]
    data_assets = [
        row
        for row in db.scalars(select(DataAsset).where(DataAsset.source == item.name)).all()
        if not (row.extra or {}).get("superseded")
    ]
    return {
        "file": serialize_file(item),
        "findings": [_serialize_detection(item) for item in findings],
        "data_assets": [_serialize_data_asset(item) for item in data_assets],
    }


@router.get("/files/{file_id}/download")
def file_download(file_id: int, db: Session = Depends(get_db)) -> FileResponse:
    item = db.get(FileRecord, file_id)
    if not item or not Path(item.path).is_file():
        raise HTTPException(404, "file not found")
    return FileResponse(item.path, filename=item.name, media_type="application/octet-stream")


@router.post("/files/{file_id}/analyze")
def analyze_file(file_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, "metadata", {"file_id": file_id})
    dispatch_task_row(ANALYZE_METADATA, task.id, file_id)
    return serialize_task(task)
