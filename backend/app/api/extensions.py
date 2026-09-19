"""Probe inventory, intelligence and DLP administration APIs."""
from datetime import UTC, datetime, timedelta
from typing import Literal
import ipaddress
import re
from app.api.data_collection import router as data_collection_router
from app.api.data_collection import queue_data_asset_scan as queue_data_asset_scan
from app.api.data_collection import data_asset_inventory as data_asset_inventory
from app.api.data_collection import data_asset_progress as data_asset_progress
from app.services.data_objects.progress import PROGRESS_FIELDS as PROGRESS_FIELDS
from app.services.data_objects.progress import progress_percent as progress_percent
from app.services.data_objects.progress import progress_stage as progress_stage
from app.api.data_collection_schemas import DataAssetScanConfig as DataAssetScanConfig
from app.api.data_collection_schemas import DataAssetColumn as DataAssetColumn
from app.api.data_collection_schemas import ProbeDataAsset as ProbeDataAsset
from app.api.data_collection_schemas import DataAssetReport as DataAssetReport
from app.api.data_collection_schemas import DataAssetProgress as DataAssetProgress
from app.services.probe_task_service import (
    TERMINAL, expire_probe_tasks,
    queue_probe_scan as queue_probe_scan,
    queue_probe_data_asset_job as queue_probe_data_asset_job,
)

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.dependencies import authenticated_probe as authenticated_probe
# DataAsset is no longer written directly here: the object model owns the data
# and data_object_service derives the legacy row in the same transaction.
from app.models import Asset, Probe, Task, IOC, SystemSetting, AnalysisResult
from app.services.asset_service import classify_service
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


#: Coverage keys a progress push is allowed to contribute, in display order.


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

@router.get('/dlp/transfers/{task_id}/{object_id}/content')
def dlp_transfer_content(task_id: int, object_id: int, download: bool = False, db: Session = Depends(get_db)):
    from fastapi.responses import FileResponse
    from app.core.config import settings
    result = db.scalar(select(AnalysisResult).where(AnalysisResult.task_id == task_id,
                       AnalysisResult.module == 'dlp').order_by(AnalysisResult.id.desc()))
    obj = next((item for item in (result.content.get('objects', []) if result else [])
                if item.get('id') == object_id and item.get('binary_available')), None)
    if not obj or not re.fullmatch(r'[a-f0-9]{64}', str(obj.get('sha256', ''))):
        raise HTTPException(404, '未保留该对象的二进制证据；历史 PCAP 请重新分析')
    path = settings.storage_dir / 'dlp_objects' / obj['sha256']
    if not path.is_file():
        raise HTTPException(404, '二进制证据已清理，请重新分析原始 PCAP')
    if download:
        return FileResponse(path, media_type='application/octet-stream', filename=obj['sha256'] + '.bin',
                            headers={'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store'})
    with path.open('rb') as handle:
        preview = handle.read(4096)
    return {'hex': preview.hex(), 'preview_bytes': len(preview), 'size': obj['size'],
            'truncated': obj['size'] > len(preview), 'sha256': obj['sha256'], 'complete': obj['complete']}


# Collection routes have their own module; register them exactly once.

router.include_router(data_collection_router)
