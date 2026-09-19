"""Rule authoring: the DLP/sensitive rule catalogue and manual rule imports.

The offline vulnerability-library maintenance (CVE entries and the Grype
database jobs) lives in ``api/integrations.py`` with the rest of the
``/offline`` surface.
"""
import json
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models import SystemSetting
from app.services.audit_service import record_audit
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


@router.get('/rule-sources')
def list_rule_sources(db: Session = Depends(get_db)):
    """每个引擎的规则来源：文件数、上游发布方、能否在线拉取。

    控制台的「引擎总览」用它说明规则的出处，运维用它判断某个引擎是否需要
    在线更新；平台自研规则（无上游）在这里 refreshable=false。
    """
    from app.rules import library
    from app.rules.catalog import CATALOG
    from app.rules import sync as rule_sync

    state_row = db.scalar(select(SystemSetting).where(SystemSetting.key == 'rule_source_state'))
    state = state_row.value if state_row and isinstance(state_row.value, dict) else {}
    sources = {item['engine']: item for item in rule_sync.sources()}
    items = []
    for source in CATALOG:
        entry = sources.get(source.engine)
        items.append({
            'engine': source.engine,
            'label': source.label,
            'rule_type': source.rule_type,
            'rule_files': len(library.rule_files(source.engine)),
            'refreshable': source.refreshable,
            'source_name': source.source_name,
            'source_url': source.source_url,
            'scope': source.scope,
            'managed_by': 'upstream' if source.refreshable else 'platform',
            'last_sync': state.get(source.engine, {}),
            'refresh_supported': bool(entry),
        })
    return {'items': items, 'total': len(items)}


class RuleSyncRequest(BaseModel):
    engines: list[str] = Field(default_factory=list, max_length=15)


@router.post('/rules/sync')
def sync_rules(request: Request, payload: RuleSyncRequest, db: Session = Depends(get_db)):
    """在线拉取引擎规则。

    只拉取 catalog 声明的上游；未指定 engines 时拉取全部可在线更新的引擎。
    拉取失败不会破坏现有规则（写盘前先按引擎原生格式校验），并把失败原因
    原样返回，便于离线环境判断是网络不可达还是上游变更。
    """
    from app.rules import sync as rule_sync

    requested = payload.engines
    if requested:
        targets = list(dict.fromkeys(requested))
        unknown = [item for item in targets if item not in {src['engine'] for src in rule_sync.sources()}]
        if unknown:
            raise HTTPException(422, f'不支持在线拉取的引擎: {", ".join(unknown)}')
    else:
        targets = [src['engine'] for src in rule_sync.sources()]
    results = [rule_sync.refresh(engine).to_dict() for engine in targets]
    summary = {
        'updated': sum(1 for item in results if item['status'] == 'updated'),
        'failed': sum(1 for item in results if item['status'] == 'failed'),
        'files': sum(int(item['files']) for item in results),
        'results': results,
    }
    row = db.scalar(select(SystemSetting).where(SystemSetting.key == 'rule_source_state'))
    previous = dict(row.value) if row and isinstance(row.value, dict) else {}
    for item in results:
        previous[item['engine']] = {
            'status': item['status'], 'files': item['files'], 'source': item['source'],
            'at': datetime.now(UTC).isoformat(), 'detail': item['detail'][:300],
        }
    if row:
        row.value = previous
    else:
        db.add(SystemSetting(key='rule_source_state', value=previous))
    db.commit()
    record_audit(db, request, action='rules.sync', target='rules', details=summary)
    return summary


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
