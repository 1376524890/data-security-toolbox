"""Sensitive-data (DLP) rule catalogue: the entity rules the console edits.

The engine-rule corpus (browsing rules, their upstream sources, the online
refresh and the manual Suricata/YARA import) lives in ``api/rules.py``, and the
offline vulnerability-library maintenance in ``api/integrations.py``; both used
to share this module.
"""
# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import SystemSetting
from app.services import rule_noise
from app.services.rule_library import (
    managed_rules,
    rule_confidence,
    save_manual_rule,
    sensitive_entity,
    set_rule_enabled,
    update_presidio,
)

router = APIRouter(prefix='/api/v1', tags=['rule-libraries'])


@router.get('/dlp/rules')
def list_dlp_rules(db: Session = Depends(get_db)):
    from app.services import sensitive_engine
    from app.services.dlp import normalize_policy
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


@router.get('/dlp/rules/noise')
def dlp_rule_noise(limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)):
    """Which rules raise the most, and how much of it the platform would still raise.

    Read-only: every number is an aggregate of rows that already exist, so an
    operator can rank the rules by noise before deciding what to fix or switch off.
    """
    return rule_noise.noise_report(db, limit=limit)


@router.post('/dlp/rules/{identifier}/replay')
def replay_dlp_rule(identifier: str, db: Session = Depends(get_db)):
    """Dry-run one rule over the原文 already stored against it.

    Nothing is written; the answer is how much of that history the rule, as it
    stands now, still matches -- including its validator.
    """
    result = rule_noise.replay(db, identifier)
    if result is None:
        raise HTTPException(404, '规则不存在')
    return result


@router.post('/dlp/rules')
def add_dlp_rule(payload: dict, db: Session = Depends(get_db)):
    try:
        rule = save_manual_rule(payload)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    # The working copy of the rule set is what a publish packs for the probes;
    # without this the rule would only ever be enforced on the platform.
    from app.services import ruleset_service
    sync = ruleset_service.sync_analyst_rules(db)
    db.commit()
    return {**rule, 'working_copy': sync}


@router.post('/dlp/rules/presidio/update')
def download_presidio(db: Session = Depends(get_db)):
    try:
        result = update_presidio()
    except Exception as exc:
        raise HTTPException(400, f'Presidio 导入失败: {exc}') from exc
    from app.services import ruleset_service
    sync = ruleset_service.sync_analyst_rules(db)
    db.commit()
    return {**result, 'working_copy': sync}


class RuleEnabled(BaseModel):
    enabled: bool


@router.patch('/dlp/rules/{identifier}')
def set_dlp_rule(identifier: str, payload: RuleEnabled, db: Session = Depends(get_db)):
    from app.engine.data_engine.engine import REGEX_RULES
    from app.services.dlp import DEFAULT_POLICY
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
    updated = set_rule_enabled(identifier, payload.enabled)
    if updated is None:
        raise HTTPException(404, '规则不存在')
    # The working copy of the rule set is what a publish packs for the probes;
    # without this the flag would only ever be enforced on the platform.
    from app.services import ruleset_service
    sync = ruleset_service.sync_analyst_rules(db)
    db.commit()
    return {**updated, 'working_copy': sync}
