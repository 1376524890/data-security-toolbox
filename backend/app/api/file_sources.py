"""Manage shared file sources; secrets are write-only."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from app.core.database import get_db
from app.core.security import require_active_admin
from app.models import FileSource
from app.api.pagination import paginate, page_response
from app.api.dependencies import dispatch_task
from app.services.audit_service import record_audit
from app.services.file_scan import service
from app.services.file_scan.adapters import SourceError
from app.services.task_dispatch import FILE_SOURCE_SCAN

router = APIRouter(tags=['file-sources'])

class SourcePayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    protocol: str = 'ftp'
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=0, ge=0, le=65535)
    username: str = Field(default='', max_length=128)
    password: str | None = Field(default=None, max_length=512)
    root_path: str = Field(default='/', max_length=1024)
    host_key_sha256: str = Field(default='', max_length=128)
    enabled: bool = True
    limits: dict[str, int] = Field(default_factory=dict)
    #: Subdirectories the walk skips. A bare name (``node_modules``) excludes that
    #: directory anywhere below the root; an absolute path excludes one subtree.
    #: An empty list means the platform default set (see
    #: ``services.file_scan.service.DEFAULT_EXCLUDES``): dependency and VCS stores
    #: are not the checked organisation's own data and produced most of this
    #: platform's false positives in practice. ``GET /file-sources`` returns
    #: ``effective_exclude_paths`` so the console can show what will really be
    #: skipped instead of an empty list that looks like "nothing is excluded".
    exclude_paths: list[str] = Field(default_factory=list, max_length=64)
    interval_minutes: int = Field(default=0, ge=0, le=43200)


def get_source(db, source_id):
    row = db.get(FileSource, source_id)
    if not row:
        raise HTTPException(404, '文件源不存在')
    return row


def guard(call):
    try:
        return call()
    except (SourceError, ValueError) as exc:
        raise HTTPException(409 if str(exc) == 'source_busy' else 422, str(exc)) from exc


@router.get('/file-sources')
def listing(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db=Depends(get_db)):
    result = paginate(db, select(FileSource).order_by(FileSource.id.desc()), page, page_size)
    return page_response([service.serialize(x) for x in result['items']], page, page_size, result['total'])


@router.post('/file-sources', dependencies=[Depends(require_active_admin)])
def create(payload: SourcePayload, request: Request, db=Depends(get_db)):
    row = guard(lambda: service.save(db, payload.model_dump()))
    record_audit(db, request, action='file_source.create', target=str(row.id), details={'protocol': row.protocol})
    db.commit()
    return service.serialize(row)


@router.put('/file-sources/{source_id}', dependencies=[Depends(require_active_admin)])
def update(source_id: int, payload: SourcePayload, request: Request, db=Depends(get_db)):
    row = guard(lambda: service.save(db, payload.model_dump(), get_source(db, source_id)))
    record_audit(db, request, action='file_source.update', target=str(row.id),
                 details={'root_path': row.root_path, 'enabled': row.enabled})
    db.commit()
    return service.serialize(row)


@router.delete('/file-sources/{source_id}', dependencies=[Depends(require_active_admin)])
def remove(source_id: int, request: Request, db=Depends(get_db)):
    """Remove one configuration; what it already collected stays in the catalogue."""
    row = get_source(db, source_id)
    name = row.name
    guard(lambda: service.remove(db, row))
    record_audit(db, request, action='file_source.delete', target=str(source_id),
                 details={'name': name})
    db.commit()
    return {'id': source_id, 'deleted': True}


@router.post('/file-sources/{source_id}/{operation}', dependencies=[Depends(require_active_admin)])
def start(source_id: int, operation: str, request: Request, db=Depends(get_db)):
    if operation not in {'scan', 'test'}:
        raise HTTPException(404, 'unknown operation')
    row = get_source(db, source_id)
    task = guard(lambda: service.queue(db, row, operation))
    record_audit(db, request, action='file_source.' + operation, target=str(row.id), details={'task_id': task.id})
    db.commit()
    dispatch_task(task.id, FILE_SOURCE_SCAN, row.id)
    return {'id': task.id, 'status': task.status}
