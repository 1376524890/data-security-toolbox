"""Probe inventory, intelligence and DLP administration APIs."""
from datetime import UTC, datetime, timedelta
from typing import Literal
import ipaddress
import re
from app.services import data_object_service
from app.services.probe_task_service import TERMINAL, expire_probe_tasks

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_probe_headers
# DataAsset is no longer written directly here: the object model owns the data
# and data_object_service derives the legacy row in the same transaction.
from app.models import Asset, Probe, Task, IOC, SystemSetting, AnalysisResult
from app.services.asset_service import classify_service
from app.services.report_guard import validate_report
from app.services.rule_library import MIN_ALERT_CONFIDENCE

from app.services.dlp_service import DEFAULT_POLICY

router = APIRouter(prefix='/api/v1')


class ScanConfig(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=32)
    ports: list[int] = Field(default=[22, 80, 443, 445, 3306, 5432, 6379, 8080], min_length=1, max_length=256)
    max_hosts: int = Field(default=256, ge=1, le=1024)
    concurrency: int = Field(default=32, ge=1, le=64)
    connect_timeout: float = Field(default=.5, ge=.1, le=3)
    timeout_seconds: int = Field(default=120, ge=1, le=600)

    @field_validator('targets')
    @classmethod
    def targets_valid(cls, values):
        for value in values:
            if ipaddress.ip_network(value, strict=False).num_addresses > 1026:
                raise ValueError('Target range too large')
        return values

    @field_validator('ports')
    @classmethod
    def ports_valid(cls, values):
        if any(p < 1 or p > 65535 for p in values):
            raise ValueError('Invalid TCP port')
        return sorted(set(values))


class InventoryAsset(BaseModel):
    ip: str = Field(max_length=64)
    port: int = Field(ge=1, le=65535)
    protocol: Literal['tcp'] = 'tcp'
    service: str = Field(default='unknown', max_length=128)
    banner: str = Field(default='', max_length=1024)
    tls: dict = Field(default_factory=dict)

    @field_validator('ip')
    @classmethod
    def ip_valid(cls, value):
        return str(ipaddress.ip_address(value))


class InventoryReport(BaseModel):
    report_id: str = Field(min_length=1, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')
    task_id: int | None = None
    assets: list[InventoryAsset] = Field(default_factory=list, max_length=8192)
    scanned_hosts: list[str] = Field(default_factory=list, max_length=1024)
    ports: list[int] = Field(default_factory=list, max_length=256)
    complete: bool = True
    error: str = Field(default='', max_length=500)
    observed_at: str = Field(default='', max_length=64)
    scanner: str = Field(default='tcp-connect', max_length=64)


def authenticated_probe(probe_id, request, db):
    probe = require_probe_headers(request, db)
    if not probe or probe.id != probe_id:
        raise HTTPException(403, 'probe id mismatch')
    return probe


def queue_probe_scan(db: Session, probe_id: int, config: dict) -> Task:
    """Queue one bounded scan job for a probe (shared by the admin and scan APIs)."""
    expire_probe_tasks(db)
    active = db.scalar(select(Task).where(Task.kind == 'probe_scan', Task.payload['probe_id'].as_integer() == probe_id,
                                         Task.status.in_(['Pending', 'Running'])))
    if active:
        raise HTTPException(409, 'Probe already has an active scan job')
    task = Task(kind='probe_scan', status='Pending', progress=0, current_stage='等待探针领取',
                payload={'probe_id': probe_id, 'config': config})
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


@router.post('/probes/{probe_id}/scan-jobs')
def queue_scan(probe_id: int, payload: ScanConfig, db: Session = Depends(get_db)):
    if not db.get(Probe, probe_id):
        raise HTTPException(404, 'probe not found')
    task = queue_probe_scan(db, probe_id, payload.model_dump())
    return {'id': task.id, 'status': task.status, 'location': 'probe'}


COMMAND_KINDS = {'probe_scan': 'asset_scan', 'data_asset_scan': 'data_asset_scan'}
COMMAND_STAGES = {'probe_scan': '探针本地资产扫描', 'data_asset_scan': '探针本地数据资产采集'}


@router.get('/probes/{probe_id}/commands')
def probe_commands(probe_id: int, request: Request, db: Session = Depends(get_db)):
    authenticated_probe(probe_id, request, db)
    expire_probe_tasks(db)
    db.commit()
    tasks = db.scalars(select(Task).where(Task.kind.in_(list(COMMAND_KINDS)), Task.payload['probe_id'].as_integer() == probe_id,
                                        Task.status.in_(['Pending', 'Running'])).order_by(Task.id).with_for_update()).all()
    now = datetime.now(UTC)
    for task in tasks:
        if task.status == 'Running':
            continue
        task.status, task.current_stage = 'Running', COMMAND_STAGES.get(task.kind, '探针本地任务')
        task.started_at = now
        task.updated_at = now
        db.commit()
        return {'commands': [{'id': task.id, 'kind': COMMAND_KINDS[task.kind], 'config': task.payload['config']}]}
    return {'commands': []}


@router.get('/probes/{probe_id}/command-status')
def command_status(probe_id: int, task_id: int, request: Request, db: Session = Depends(get_db)):
    authenticated_probe(probe_id, request, db)
    expire_probe_tasks(db)
    db.commit()
    task = db.get(Task, task_id)
    if not task or task.payload.get('probe_id') != probe_id:
        raise HTTPException(404, 'task not found')
    return {'stop': task.status in TERMINAL or bool(task.payload.get('deleted')), 'status': task.status}


@router.post('/probes/{probe_id}/inventory')
def inventory(probe_id: int, payload: InventoryReport, request: Request, db: Session = Depends(get_db)):
    probe = authenticated_probe(probe_id, request, db)
    # Serialize reports from one probe; atomic asset upserts and replay handling.
    db.execute(select(Probe.id).where(Probe.id == probe_id).with_for_update())
    task = db.scalar(select(Task).where(Task.id == payload.task_id).with_for_update()) if payload.task_id else db.scalar(select(Task).where(
        Task.kind == 'probe_scan', Task.payload['probe_id'].as_integer() == probe_id,
        Task.payload['report_id'].as_string() == payload.report_id))
    if payload.task_id and (not task or task.kind != 'probe_scan' or task.payload.get('probe_id') != probe_id):
        raise HTTPException(403, 'scan task does not belong to probe')
    if task and (task.status in TERMINAL or task.payload.get('deleted')):
        return {'id': task.id, 'duplicate': True, 'assets': task.result.get('assets', 0)}
    if not task:
        task = Task(kind='probe_scan', payload={'probe_id': probe_id, 'report_id': payload.report_id})
        db.add(task)
    now = datetime.now(UTC)
    existing = db.scalars(select(Asset).where(Asset.probe_id == probe_id)).all()
    index = {(a.ip, a.port, a.protocol): a for a in existing}
    seen = set()
    for item in payload.assets:
        key = (item.ip, item.port, item.protocol)
        row = index.get(key)
        if not row:
            row = Asset(probe_id=probe_id, ip=item.ip, port=item.port, protocol=item.protocol)
            db.add(row)
            index[key] = row
        row.service = item.service
        row.asset_type = classify_service(item.port, item.service)
        row.last_seen = now
        row.extra = {**(row.extra or {}), 'source': 'probe_scan', 'status': 'open',
                     'banner': item.banner, 'tls': item.tls, 'scanner': payload.scanner}
        seen.add(key)
    if payload.complete and not payload.error:
        for key, row in index.items():
            if row.ip in payload.scanned_hosts and row.port in payload.ports and key not in seen:
                row.extra = {**(row.extra or {}), 'status': 'not_observed', 'checked_at': now.isoformat()}
    task.status = 'Failed' if payload.error else ('Success' if payload.complete else 'Partial')
    task.progress, task.current_stage, task.finished_at = 100, '探针扫描完成', now
    task.error = payload.error
    task.result = {'assets': len(seen), 'complete': payload.complete, 'report_id': payload.report_id, 'location': 'probe',
                   'hosts': payload.scanned_hosts, 'ports': payload.ports, 'engine': payload.scanner, 'errors': payload.error}
    probe.extra = {**(probe.extra or {}), 'last_scan': {**task.result, 'status': task.status, 'at': now.isoformat()}}
    probe.last_seen = now
    db.commit()
    return {'id': task.id, 'duplicate': False, 'assets': len(seen)}


class DataAssetScanConfig(BaseModel):
    paths: list[str] = Field(default_factory=list, max_length=32, description="目标服务器上要采集的目录")
    max_files: int = Field(default=200, ge=1, le=2000)
    max_depth: int = Field(default=3, ge=0, le=8)
    include_databases: bool = True
    timeout_seconds: int = Field(default=120, ge=5, le=1800)
    #: Scope filters. A bare name filters that directory anywhere below a root; an
    #: absolute path excludes exactly that subtree. ``file_types`` is an extension
    #: allow-list, and an empty one keeps every type in scope.
    exclude_paths: list[str] = Field(default_factory=list, max_length=32)
    file_types: list[str] = Field(default_factory=list, max_length=32)
    #: Optional versioned profile. When set, its snapshot supplies the config and
    #: the fields above act as explicit overrides.
    profile_id: int | None = Field(default=None, ge=1)

    @field_validator('paths')
    @classmethod
    def paths_valid(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            item = str(value).strip()
            if not item:
                continue
            if '..' in item.split('/') or not item.startswith('/') or len(item) > 512:
                raise ValueError('paths must be absolute Linux paths without ".."')
            if item not in cleaned:
                cleaned.append(item)
        return cleaned

    @field_validator('exclude_paths')
    @classmethod
    def excludes_valid(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            item = str(value).strip().rstrip('/')
            if not item:
                continue
            # A bare directory name and an absolute subtree are both accepted, but
            # neither may walk upwards out of the scanned tree.
            if '..' in item.split('/') or len(item) > 512:
                raise ValueError('exclude_paths must not contain ".."')
            if item not in cleaned:
                cleaned.append(item)
        return cleaned

    @field_validator('file_types')
    @classmethod
    def file_types_valid(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            item = str(value).strip().lower()
            if not item:
                continue
            if not item.startswith('.'):
                item = '.' + item
            if item not in cleaned:
                cleaned.append(item)
        return cleaned


class DataAssetColumn(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    header_name: str = Field(default='', max_length=256)
    sheet_name: str = Field(default='', max_length=128)
    column_index: int | None = Field(default=None, ge=0, le=65535)
    detected_type: str = Field(default='', max_length=64)
    inferred_type: str = Field(default='', max_length=32)
    sensitivity: str = Field(default='Unknown', max_length=16)
    confidence: float = Field(default=0.0, ge=0, le=1)
    categories: list[str] = Field(default_factory=list, max_length=16)
    count: int = Field(default=0, ge=0)
    sample_size: int = Field(default=0, ge=0)
    sample_hit_count: int = Field(default=0, ge=0)
    rule_ids: list[str] = Field(default_factory=list, max_length=64)


class ProbeDataAsset(BaseModel):
    name: str = Field(min_length=1, max_length=512)
    asset_type: str = Field(default='file', max_length=64)
    sensitivity: str = Field(default='Low', max_length=16)
    path: str = Field(default='', max_length=1024)
    size: int = Field(default=0, ge=0)
    sha256: str = Field(default='', max_length=64)
    # Stage 4 identity fields. An old probe omits them and the ingestion derives
    # the same answer from ``sha256`` plus the fingerprint evidence.
    hash_type: str = Field(default='', max_length=32)
    identity_confidence: float | None = Field(default=None, ge=0, le=1)
    level: str = Field(default='', max_length=8)
    modified_at: str = Field(default='', max_length=64)
    categories: list[str] = Field(default_factory=list, max_length=16)
    counts: dict[str, int] = Field(default_factory=dict)
    columns: list[DataAssetColumn] = Field(default_factory=list, max_length=256)
    evidence: dict = Field(default_factory=dict)
    coverage: str = Field(default='', max_length=16)
    termination_reason: str = Field(default='', max_length=64)
    scan_id: str = Field(default='', max_length=64)
    ruleset_version: str = Field(default='', max_length=64)
    engine_version: str = Field(default='', max_length=64)
    profile_version: str = Field(default='', max_length=64)


class DataAssetReport(BaseModel):
    """Inventory produced on the probe host itself; no raw content is uploaded.

    New in 1.1: ``schema_version``, ``scan_id``, the version triple, the aggregated
    ``budget``/``coverage`` and an explicit ``completed_scope``. Every one of them
    is optional so a 3.3.1 probe keeps uploading exactly what it always did, and
    the ingestion falls back to the legacy meaning instead of assuming coverage.
    """

    report_id: str = Field(min_length=1, max_length=64, pattern=r'^[a-zA-Z0-9_-]+$')
    task_id: int | None = None
    schema_version: str = Field(default='', max_length=16)
    scan_id: str = Field(default='', max_length=64)
    assets: list[ProbeDataAsset] = Field(default_factory=list, max_length=4096)
    databases: list[ProbeDataAsset] = Field(default_factory=list, max_length=256)
    scanned_paths: list[str] = Field(default_factory=list, max_length=64)
    max_depth: int | None = Field(default=None, ge=0, le=8)
    complete: bool = True
    completed_scope: bool | None = None
    error: str = Field(default='', max_length=500)
    reason_code: str = Field(default='', max_length=64)
    termination_reason: str = Field(default='', max_length=64)
    observed_at: str = Field(default='', max_length=64)
    scanner: str = Field(default='probe-file-inventory', max_length=64)
    ruleset_version: str = Field(default='', max_length=64)
    engine_version: str = Field(default='', max_length=64)
    profile_version: str = Field(default='', max_length=64)
    counts: dict[str, int] = Field(default_factory=dict)
    totals: dict = Field(default_factory=dict)
    budget: dict = Field(default_factory=dict)
    coverage: dict = Field(default_factory=dict)
    degraded_capabilities: list[str] = Field(default_factory=list, max_length=32)
    report_guard: dict = Field(default_factory=dict, description="探针侧报告清洗计数（脱敏/截断/丢弃字段）")


def queue_probe_data_asset_job(db: Session, probe_id: int, config: dict, *, profile=None) -> Task:
    """Queue one bounded data-asset job, optionally from a versioned ScanProfile.

    The resolved configuration is copied into the task payload. That copy is the
    authoritative scope: editing the profile afterwards cannot change what a probe
    was already asked to do.
    """
    probe = db.get(Probe, probe_id)
    if not probe:
        raise HTTPException(404, 'probe not found')
    version = str((probe.extra or {}).get('agent_version') or (probe.extra or {}).get('version') or '')
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)', version)
    if match and tuple(map(int, match.groups())) < (3, 3, 0):
        from app.core.config import settings

        raise HTTPException(409, f'探针版本 {version} 不支持数据资产采集，请在探针部署页升级到 {settings.probe_agent_version}')
    expire_probe_tasks(db)
    active = db.scalar(select(Task).where(Task.kind == 'data_asset_scan',
                                          Task.payload['probe_id'].as_integer() == probe_id,
                                          Task.status.in_(['Pending', 'Running'])))
    if active:
        raise HTTPException(409, 'Probe already has an active data asset job')
    task_payload: dict = {'probe_id': probe_id, 'config': config}
    if profile is not None:
        # profile_id stays a top-level key so it is queryable for the reference guard.
        task_payload['profile_id'] = profile.id
        task_payload['profile_snapshot'] = {
            'profile_id': profile.id, 'profile_name': profile.name,
            'profile_version': profile.version, 'config': config,
        }
    task = Task(kind='data_asset_scan', status='Pending', progress=0, current_stage='等待探针领取',
                payload=task_payload)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


@router.post('/probes/{probe_id}/data-assets/jobs')
def queue_data_asset_scan(probe_id: int, payload: DataAssetScanConfig, db: Session = Depends(get_db)):
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
            config['paths'] = payload.paths
        if payload.exclude_paths:
            config['exclude_paths'] = payload.exclude_paths
        if payload.file_types:
            config['file_types'] = payload.file_types
        if payload.max_files != DataAssetScanConfig.model_fields['max_files'].default:
            config['max_files'] = payload.max_files
        if payload.max_depth != DataAssetScanConfig.model_fields['max_depth'].default:
            config['max_depth'] = payload.max_depth
        if payload.timeout_seconds != DataAssetScanConfig.model_fields['timeout_seconds'].default:
            config['timeout_seconds'] = payload.timeout_seconds
        if not config.get('paths'):
            raise HTTPException(400, '扫描配置未设置 include_paths，探针没有可扫描的目录')
    else:
        config = payload.model_dump(exclude={'profile_id'})
    task = queue_probe_data_asset_job(db, probe_id, config, profile=profile)
    return {'id': task.id, 'status': task.status, 'location': 'probe'}


@router.post('/probes/{probe_id}/data-assets')
def data_asset_inventory(probe_id: int, payload: DataAssetReport, request: Request, db: Session = Depends(get_db)):
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
        raise HTTPException(422, detail={'error': 'unsafe_report',
                                         'violations': [item.to_dict() for item in violations]})
    db.execute(select(Probe.id).where(Probe.id == probe_id).with_for_update())
    task = db.scalar(select(Task).where(Task.id == payload.task_id).with_for_update()) if payload.task_id else db.scalar(select(Task).where(
        Task.kind == 'data_asset_scan', Task.payload['probe_id'].as_integer() == probe_id,
        Task.payload['report_id'].as_string() == payload.report_id))
    if payload.task_id and (not task or task.kind != 'data_asset_scan' or task.payload.get('probe_id') != probe_id):
        raise HTTPException(403, 'data asset task does not belong to probe')
    if task and (task.status in TERMINAL or task.payload.get('deleted')):
        return {'id': task.id, 'duplicate': True, 'assets': task.result.get('assets', 0)}
    if not task:
        task = Task(kind='data_asset_scan', payload={'probe_id': probe_id, 'report_id': payload.report_id})
        db.add(task)
        db.flush()
    now = datetime.now(UTC)
    outcome = data_object_service.ingest_report(db, probe, body, task)
    stored = outcome['stored']
    task.status = 'Failed' if payload.error else ('Success' if payload.complete else 'Partial')
    task.progress, task.current_stage, task.finished_at = 100, '探针数据资产采集完成', now
    task.error = payload.error
    task.result = {'assets': stored, 'complete': payload.complete, 'report_id': payload.report_id,
                   'location': 'probe', 'paths': payload.scanned_paths,
                   'databases': len(payload.databases), 'host': probe.ip_address or probe.hostname,
                   'scan_id': outcome['scan_id'],
                   'schema_version': data_object_service.detect_report_schema(body),
                   'complete_scope': outcome['complete_scope'],
                   'not_observed': outcome['not_observed'],
                   'stale_entries': outcome['late_skipped'],
                   'ruleset_version': payload.ruleset_version,
                   'engine_version': payload.engine_version,
                   'profile_version': payload.profile_version,
                   'coverage': payload.coverage, 'budget': payload.budget}
    probe.extra = {**(probe.extra or {}), 'last_data_asset_scan': {**task.result, 'status': task.status, 'at': now.isoformat()}}
    probe.last_seen = now
    db.add(AnalysisResult(task_id=task.id, module='data_assets', content=task.result,
                          risk_level='High' if any(item.sensitivity in ('Critical', 'High') for item in [*payload.assets, *payload.databases]) else 'Low'))
    db.commit()
    return {'id': task.id, 'duplicate': False, 'assets': stored, 'scan_id': outcome['scan_id'],
            'complete_scope': outcome['complete_scope'], 'not_observed': outcome['not_observed'],
            # Entries dropped because a newer scan had already been applied.
            'stale': outcome['late_skipped']}


class DataAssetProgress(BaseModel):
    """Aggregated progress for a running job. Never a terminal transition."""

    task_id: int
    scan_id: str = Field(default='', max_length=64)
    current_path: str = Field(default='', max_length=1024)
    coverage: dict = Field(default_factory=dict)


@router.post('/probes/{probe_id}/data-assets/progress')
def data_asset_progress(probe_id: int, payload: DataAssetProgress, request: Request,
                        db: Session = Depends(get_db)):
    """Record progress on a running task, at whatever rate the probe chose.

    Deliberately narrow: progress cannot set a task's status, cannot clear its
    error and cannot resurrect a finished task. That is what keeps a stalled
    probe from freezing the task lifecycle, and a failed progress push from
    failing the scan.
    """
    authenticated_probe(probe_id, request, db)
    task = db.get(Task, payload.task_id)
    if not task or task.kind != 'data_asset_scan' or (task.payload or {}).get('probe_id') != probe_id:
        raise HTTPException(404, 'data asset task not found')
    if task.status in TERMINAL or (task.payload or {}).get('deleted'):
        return {'id': task.id, 'status': task.status, 'applied': False}
    coverage = payload.coverage if isinstance(payload.coverage, dict) else {}
    estimated = progress_percent(coverage)
    task.progress = estimated['percent']
    task.current_stage = progress_stage(coverage, payload.current_path)
    task.payload = {**(task.payload or {}), 'progress': {
        **{key: coverage.get(key) for key in
           ('max_files', 'files_discovered', 'files_analyzed', 'files_skipped',
            'directories_scanned', 'bytes_read', 'sensitive_assets', 'detections',
            'elapsed_seconds', 'termination_reason')},
        'current_path': payload.current_path, 'scan_id': payload.scan_id,
        'percent': estimated['percent'], 'estimated': estimated['estimated'],
        'basis': estimated['basis'],
        'reported_at': datetime.now(UTC).isoformat()}}
    db.commit()
    return {'id': task.id, 'status': task.status, 'applied': True}


#: Coverage keys a progress push is allowed to contribute, in display order.
PROGRESS_FIELDS = (
    ('files_discovered', '已发现文件'), ('files_analyzed', '已分析文件'),
    ('directories_scanned', '已扫描目录'), ('bytes_read', '已读取字节'),
)


def progress_percent(coverage: dict) -> dict:
    """A bounded estimate, labelled as one, or explicitly unknown.

    ``max_files`` is the only total both sides know without a second walk, so the
    percentage is ``files_analyzed / max_files`` - an upper bound on how far the
    scan has come, never a claim about how much data exists. With no usable
    denominator the progress is reported as unknown instead of invented.
    """
    limit = coverage.get('max_files') or coverage.get('files_expected')
    analyzed = coverage.get('files_analyzed')
    try:
        limit, analyzed = int(limit), int(analyzed)
    except (TypeError, ValueError):
        return {'percent': 0, 'estimated': True, 'basis': 'unknown'}
    if limit <= 0 or analyzed < 0:
        return {'percent': 0, 'estimated': True, 'basis': 'unknown'}
    basis = 'files_analyzed/max_files'
    if coverage.get('files_expected'):
        basis = 'files_analyzed/files_expected'
        return {'percent': max(0, min(int(analyzed * 100 / limit), 99)), 'estimated': False,
                'basis': basis}
    # Capped below 100: only the final report may declare the scan finished.
    return {'percent': max(0, min(int(analyzed * 100 / limit), 99)), 'estimated': True,
            'basis': basis}


def progress_stage(coverage: dict, current_path: str) -> str:
    parts = [f'{label} {coverage.get(key)}' for key, label in PROGRESS_FIELDS
             if coverage.get(key) is not None]
    detail = '，'.join(parts)
    if current_path:
        detail = f'{detail}，当前 {current_path}' if detail else f'当前 {current_path}'
    return (detail or '探针数据资产采集中')[:255]


class IocImport(BaseModel):
    content: str = Field(max_length=5 * 1024 * 1024)
    source: str = Field(default='manual', min_length=1, max_length=100, pattern=r'^[\w.-]+$')


@router.post('/intelligence/import')
def import_iocs(payload: IocImport, db: Session = Depends(get_db)):
    from app.services.intelligence_service import parse_indicators, upsert_iocs
    try:
        rows, rejected = parse_indicators(payload.content)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc))
    result = upsert_iocs(db, rows, payload.source)
    db.commit()
    return {**result, 'rejected': rejected}


@router.get('/intelligence/export')
def export_iocs(db: Session = Depends(get_db)):
    return {'items': [{'type': r.ioc_type, 'value': r.value, 'source': r.source, 'tags': r.tags}
                      for r in db.scalars(select(IOC).order_by(IOC.id).limit(20000)) if (r.extra or {}).get('enabled', True)]}


@router.post('/intelligence/{ioc_id}/toggle')
def toggle_ioc(ioc_id: int, payload: dict, db: Session = Depends(get_db)):
    row = db.get(IOC, ioc_id)
    if not row:
        raise HTTPException(404, 'IOC not found')
    row.extra = {**(row.extra or {}), 'enabled': bool(payload.get('enabled', True))}
    db.commit()
    return {'id': row.id, 'enabled': row.extra['enabled']}


@router.get('/intelligence/providers')
def providers(db: Session = Depends(get_db)):
    from app.services.intelligence_service import PROVIDERS
    from app.core.config import settings
    states = {r.key: r.value for r in db.scalars(select(SystemSetting).where(SystemSetting.key.like('intel_sync_%')))}
    return {'items': [{'id': key, 'name': spec['name'], 'key_required': spec['key_required'],
                       'configured': key == 'feodo' or bool(settings.urlhaus_auth_key if key == 'urlhaus' else settings.custom_intel_url),
                       'last_sync': states.get('intel_sync_' + key, {})} for key, spec in PROVIDERS.items()]}


@router.post('/intelligence/providers/{provider}/sync')
def start_intel_sync(provider: str, db: Session = Depends(get_db)):
    from app.services.intelligence_service import PROVIDERS
    from app.workers.tasks import sync_intelligence_task
    if provider not in PROVIDERS:
        raise HTTPException(404, 'Unknown intelligence provider')
    expire_probe_tasks(db)
    active = db.scalar(select(Task).where(Task.kind == 'intel_sync', Task.status.in_(['Pending', 'Running']), Task.payload['provider'].as_string() == provider))
    if active:
        raise HTTPException(409, 'Sync is already queued')
    recent = db.scalar(select(Task).where(Task.kind == 'intel_sync', Task.payload['provider'].as_string() == provider).order_by(Task.id.desc()))
    if recent and datetime.now(UTC) - recent.created_at.replace(tzinfo=UTC) < timedelta(minutes=5):
        raise HTTPException(429, 'Wait five minutes between feed synchronizations')
    task = Task(kind='intel_sync', status='Pending', payload={'provider': provider})
    db.add(task)
    db.commit()
    try:
        sync_intelligence_task.delay(task.id)
    except Exception:
        task.status, task.error = 'Failed', 'Task queue unavailable'
        db.commit()
        raise HTTPException(503, task.error)
    return {'id': task.id, 'status': task.status}


class DlpPolicy(BaseModel):
    enabled: bool = True
    categories: list[Literal['phone', 'id_card', 'bank_card', 'email', 'api_key', 'token']] = Field(default=['phone', 'id_card', 'email', 'api_key'], max_length=6)
    keywords: list[str] = Field(default_factory=list, max_length=100)
    fingerprints: list[str] = Field(default_factory=list, max_length=1000)
    min_matches: int = Field(default=1, ge=1, le=1000)
    min_confidence: float = Field(default=MIN_ALERT_CONFIDENCE, ge=0, le=1)
    exclude_cidrs: list[str] = Field(default_factory=lambda: list(DEFAULT_POLICY['exclude_cidrs']), max_length=50)
    # Own infrastructure (platform URL is derived automatically): host, host:port
    # or CIDR. Traffic to/from these endpoints is never reported as data loss.
    ignore_own_traffic: bool = True
    self_endpoints: list[str] = Field(default_factory=list, max_length=100)

    @field_validator('keywords')
    @classmethod
    def keywords_valid(cls, values):
        if any(not v.strip() or len(v) > 100 for v in values):
            raise ValueError('Keywords must contain 1..100 characters')
        return sorted(set(v.strip() for v in values))

    @field_validator('fingerprints')
    @classmethod
    def fingerprints_valid(cls, values):
        import re
        if any(not re.fullmatch('[a-fA-F0-9]{64}', v) for v in values):
            raise ValueError('Expected SHA256 fingerprints')
        return sorted(set(v.lower() for v in values))

    @field_validator('exclude_cidrs')
    @classmethod
    def cidrs_valid(cls, values):
        networks = []
        for value in values:
            try:
                networks.append(str(ipaddress.ip_network(value.strip(), strict=False)))
            except ValueError as exc:
                raise ValueError(f'无效网段: {value}') from exc
        return sorted(set(networks))

    @field_validator('self_endpoints')
    @classmethod
    def self_endpoints_valid(cls, values):
        import re
        cleaned = []
        for value in values:
            item = str(value).strip()
            match = re.fullmatch(r'([0-9A-Za-z._-]{1,63}(?:/[0-9]{1,2})?)(?::([0-9]{1,5}))?', item)
            if not match or (match.group(2) and not 1 <= int(match.group(2)) <= 65535):
                raise ValueError(f'无效自有端点（应为 host、host:port 或 CIDR）: {value}')
            cleaned.append(item)
        return sorted(set(cleaned))


@router.get('/dlp/policy')
def dlp_policy(db: Session = Depends(get_db)):
    from app.services.dlp_service import normalize_policy
    row = db.scalar(select(SystemSetting).where(SystemSetting.key == 'dlp_policy'))
    # Stored policies may predate a key; the UI always needs the effective values.
    return normalize_policy(row.value if row else {})


@router.post('/dlp/policy')
def save_dlp_policy(payload: DlpPolicy, db: Session = Depends(get_db)):
    row = db.scalar(select(SystemSetting).where(SystemSetting.key == 'dlp_policy'))
    if not row:
        row = SystemSetting(key='dlp_policy')
        db.add(row)
    row.value = payload.model_dump()
    db.commit()
    return row.value


@router.get('/dlp/transfers')
def dlp_transfers(pcap_id: int | None = None, db: Session = Depends(get_db)):
    query = select(AnalysisResult, Task).join(Task, AnalysisResult.task_id == Task.id).where(AnalysisResult.module == 'dlp')
    if pcap_id is not None:
        query = query.where(Task.payload['pcap_id'].as_integer() == pcap_id)
    rows = db.execute(query.order_by(AnalysisResult.id.desc()).limit(50)).all()
    items, coverage, seen = [], [], set()
    for result, task in rows:
        capture = task.payload.get('pcap_id')
        if capture in seen:
            continue
        seen.add(capture)
        coverage.append({'pcap_id': capture, **result.content.get('coverage', {})})
        items.extend({**item, 'pcap_id': capture, 'task_id': task.id} for item in result.content.get('objects', []) if not item.get('is_header') or item.get('matches'))
    return {'items': items[:2000], 'coverage': coverage, 'mode': 'passive', 'tls_decryption': False}