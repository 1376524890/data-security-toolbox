"""Sensitive-data (DLP) rule catalogue: the entity rules the console edits.

The engine-rule corpus (browsing rules, their upstream sources, the online
refresh and the manual Suricata/YARA import) lives in ``api/rules.py``, and the
offline vulnerability-library maintenance in ``api/integrations.py``; both used
to share this module.
"""
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models import SystemSetting
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
