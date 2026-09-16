"""Rule authoring and asynchronous vulnerability-library maintenance."""
import json
import re
import tempfile
import uuid
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal, get_db
from app.models import LocalCve, SystemSetting
from app.services.rule_library import (atomic_json, managed_rules, rule_confidence, save_manual_rule,
                                       sensitive_entity, update_presidio)

router = APIRouter(prefix='/api/v1', tags=['rule-libraries'])


@router.get('/dlp/rules')
def list_dlp_rules(db: Session = Depends(get_db)):
    from app.services import sensitive_engine
    from app.services.dlp_service import normalize_policy
    policy = db.scalar(select(SystemSetting).where(SystemSetting.key == 'dlp_policy'))
    effective = normalize_policy(policy.value if policy else {})
    active, threshold = effective['categories'], effective['min_confidence']
    # Built-ins are read from the shared rule pack, so the list, the stored policy
    # and the engine that runs on the probe all describe the same rules.
    builtins_by_id: dict[str, dict] = {}
    for rule in sensitive_engine.get_engine().rules:
        if not rule.get('pattern'):
            continue
        name = sensitive_engine.legacy_name(rule['entity']) or str(rule['entity']).lower()
        entry = {
            'id': name, 'rule_id': rule['rule_id'], 'name': rule['name'], 'entity': name,
            'canonical_entity': rule['entity'], 'pattern': rule['pattern'],
            'source': rule.get('rule_source') or 'builtin', 'mode': 'regex',
            'level': rule.get('level') or sensitive_engine.level_of(rule['entity']),
            'severity': sensitive_engine.severity_of(rule['entity']),
            'enabled': name in active, 'confidence': rule['confidence'],
            'sensitive': not sensitive_engine.is_structural(rule['entity']),
        }
        kept = builtins_by_id.get(name)
        if kept is None or (not kept['pattern'] and entry['pattern']):
            builtins_by_id[name] = entry
    builtins = list(builtins_by_id.values())
    # Legacy stores may predate the confidence field, so report the effective value.
    managed = [{**rule, 'confidence': rule_confidence(rule), 'sensitive': sensitive_entity(rule)} for rule in managed_rules()]
    rules = builtins + managed
    for rule in rules:
        rule['alertable'] = rule['sensitive'] and rule['confidence'] >= threshold
    return {'items': rules, 'total': len(rules)}


@router.post('/dlp/rules')
def add_dlp_rule(payload: dict):
    try:
        return save_manual_rule(payload)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post('/dlp/rules/presidio/update')
def download_presidio():
    try:
        return update_presidio()
    except Exception as exc:
        raise HTTPException(400, f'Presidio 导入失败: {exc}') from exc


class RuleEnabled(BaseModel):
    enabled: bool


@router.patch('/dlp/rules/{identifier}')
def set_dlp_rule(identifier: str, payload: RuleEnabled, db: Session = Depends(get_db)):
    from app.engine.data_engine.engine import REGEX_RULES
    from app.services.dlp_service import DEFAULT_POLICY
    if identifier in REGEX_RULES:
        row = db.scalar(select(SystemSetting).where(SystemSetting.key == 'dlp_policy'))
        if not row:
            row = SystemSetting(key='dlp_policy', value=DEFAULT_POLICY)
            db.add(row)
        policy = dict(row.value)
        categories = set(policy['categories'])
        categories.add(identifier) if payload.enabled else categories.discard(identifier)
        row.value = {**policy, 'categories': sorted(categories)}
        db.commit()
        return {'id': identifier, 'enabled': payload.enabled}
    for path in sorted((settings.integration_dir / 'dlp_rules').glob('*.json')):
        document = json.loads(path.read_text(encoding='utf-8'))
        for rule in document['rules']:
            if rule['id'] == identifier:
                rule['enabled'] = payload.enabled
                atomic_json(path, document)
                return rule
    raise HTTPException(404, '规则不存在')


class DetectionRule(BaseModel):
    rule_type: Literal['suricata', 'yara']
    name: str = Field(min_length=1, max_length=100, pattern=r'^[A-Za-z0-9_-]+$')
    content: str = Field(min_length=1, max_length=1024 * 1024)


@router.post('/rules')
def create_detection_rule(payload: DetectionRule, db: Session = Depends(get_db)):
    if payload.rule_type == 'suricata':
        from app.integrations.offline_manager import import_uploaded_offline
        result = import_uploaded_offline(db, payload.name + '.rules', payload.content.encode(), 'suricata_rules', payload.name,
                                        uuid.uuid4().hex[:12])
        if result.errors:
            raise HTTPException(422, '; '.join(result.errors))
        return result.to_dict()
    try:
        import yara
        yara.compile(source=payload.content, includes=False)
    except ImportError as exc:
        raise HTTPException(503, '缺少 yara-python，安装后才能校验并启用 YARA 规则') from exc
    except Exception as exc:
        raise HTTPException(422, f'YARA 校验失败: {exc}') from exc
    directory = settings.integration_dir / 'yara_rules'
    directory.mkdir(parents=True, exist_ok=True)
    # Unique file name avoids silently replacing an existing rule.
    target = directory / (payload.name + '_' + uuid.uuid4().hex[:12] + '.yar')
    with tempfile.NamedTemporaryFile(dir=directory, suffix='.tmp', delete=False) as handle:
        handle.write(payload.content.encode())
        temporary = Path(handle.name)
    temporary.replace(target)
    return {'imported': 1, 'path': str(target)}


class CveRule(BaseModel):
    cve_id: str = Field(pattern=r'^CVE-\d{4}-\d{4,}$')
    severity: Literal['Critical', 'High', 'Medium', 'Low', 'Unknown'] = 'Medium'
    cvss_score: float = Field(default=0, ge=0, le=10)
    description: str = Field(min_length=1, max_length=50000)


@router.post('/offline/cves')
def add_cve(payload: CveRule, db: Session = Depends(get_db)):
    existing = db.scalar(select(LocalCve).where(LocalCve.cve_id == payload.cve_id))
    if existing:
        raise HTTPException(409, 'CVE 已存在；批量更新请使用 JSON 导入')
    row = LocalCve(**{**payload.model_dump(), 'description': {'text': payload.description}, 'source': 'manual'})
    db.add(row)
    db.commit()
    return {'cve_id': row.cve_id}


def job_path(identifier):
    if not re.fullmatch('[a-f0-9]{32}', identifier):
        raise HTTPException(404, '任务不存在')
    return settings.storage_dir / 'library_jobs' / (identifier + '.json')


def run_grype_job(identifier, source=None):
    from app.services.grype_library import download_latest, import_database, import_lock
    state = {'id': identifier, 'status': 'running'}
    def progress(**values):
        state.update(values)
        atomic_json(job_path(identifier), state)
    try:
        with import_lock(), tempfile.TemporaryDirectory(dir=settings.integration_dir) as directory:
            progress(stage='starting')
            metadata = {}
            if source is None:
                source, metadata = download_latest(directory, progress)
            with SessionLocal() as db:
                result = import_database(db, source, metadata, progress)
            progress(status='completed', stage='completed', result=result)
    except Exception as exc:
        progress(status='failed', error=str(exc))
    finally:
        if source and Path(source).parent == settings.storage_dir / 'library_uploads':
            Path(source).unlink(missing_ok=True)


@router.post('/offline/grype/update', status_code=202)
def update_grype(background: BackgroundTasks):
    identifier = uuid.uuid4().hex
    state = {'id': identifier, 'status': 'queued'}
    atomic_json(job_path(identifier), state)
    background.add_task(run_grype_job, identifier)
    return state


@router.post('/offline/grype/import', status_code=202)
def upload_grype(background: BackgroundTasks, file: UploadFile = File(...)):
    from app.services.grype_library import MAX_ARCHIVE
    identifier = uuid.uuid4().hex
    directory = settings.storage_dir / 'library_uploads'
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / identifier
    try:
        size = 0
        with target.open('wb') as output:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_ARCHIVE:
                    raise HTTPException(413, '上传文件超过 2 GB；支持 .tar.zst / .tar.gz / SQLite DB')
                output.write(chunk)
        if not size:
            raise HTTPException(422, '文件为空')
    except Exception:
        target.unlink(missing_ok=True)
        raise
    state = {'id': identifier, 'status': 'queued'}
    atomic_json(job_path(identifier), state)
    background.add_task(run_grype_job, identifier, target)
    return state


@router.get('/offline/grype/jobs/{identifier}')
def grype_job(identifier: str):
    path = job_path(identifier)
    if not path.is_file():
        raise HTTPException(404, '任务不存在')
    return json.loads(path.read_text(encoding='utf-8'))
