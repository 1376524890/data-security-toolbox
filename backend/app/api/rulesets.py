"""Rule set administration and the authenticated probe download.

The probe download endpoints deliberately sit behind the same probe-token check
as the other probe APIs (`authenticated_probe`): being listed as a probe API in
the auth middleware only means "no admin session required", never "no
authentication".
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import authenticated_probe
from app.core.database import get_db
from app.core.security import get_session_user
from app.models import RuleSet, RuleSetVersion
from app.services import ruleset_service
from app.services.ruleset_service import RuleSetError

router = APIRouter(prefix="/api/v1", tags=["rule-sets"])


def _actor(db: Session, request: Request) -> str:
    try:
        user = get_session_user(db, request)
    except Exception:
        user = None
    return str(getattr(user, "username", "") or "admin")


def _rule_set_or_404(db: Session, rule_set_id: int) -> RuleSet:
    rule_set = db.get(RuleSet, rule_set_id)
    if rule_set is None:
        raise HTTPException(404, "rule set not found")
    return rule_set


def _version_summary(row: RuleSetVersion) -> dict:
    return {
        "id": row.id, "version": row.version, "status": row.status, "rule_count": row.rule_count,
        "sha256": row.sha256, "schema_version": row.schema_version, "engine_version": row.engine_version,
        "min_agent_version": row.min_agent_version, "origin_version": row.origin_version,
        "changelog": row.changelog, "published_by": row.published_by,
        "created_at": row.created_at.isoformat() if row.created_at else "",
    }


class RulePayload(BaseModel):
    rule_id: str = Field(min_length=1, max_length=128)
    name: str = ""
    entity: str = ""
    pattern: str = ""
    confidence: float = Field(default=0.5, ge=0, le=1)
    validator: str = ""
    field_hints: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    enabled: bool = True
    rule_source: str = "manual"
    description: str = ""


class PublishPayload(BaseModel):
    version: str = Field(min_length=1, max_length=64)
    changelog: str = Field(default="", max_length=512)
    min_agent_version: str = Field(default="", max_length=32)
    rules: list[RulePayload] | None = None


class RollbackPayload(BaseModel):
    to_version: str = Field(min_length=1, max_length=64)
    changelog: str = Field(default="", max_length=512)


@router.get("/rulesets")
def list_rule_sets(db: Session = Depends(get_db)) -> dict:
    ruleset_service.ensure_baseline(db)
    db.commit()
    items = []
    for rule_set in db.scalars(select(RuleSet).order_by(RuleSet.id)):
        current = ruleset_service.active_version(db, rule_set)
        working = ruleset_service.collect_rules(db, rule_set.id)
        items.append({
            "id": rule_set.id, "name": rule_set.name, "description": rule_set.description,
            "active_version": _version_summary(current) if current else None,
            "working_rule_count": len(working),
            "capabilities": ruleset_service.capabilities(),
        })
    return {"items": items, "total": len(items)}


@router.get("/rulesets/{rule_set_id}/rules")
def list_working_rules(rule_set_id: int, db: Session = Depends(get_db)) -> dict:
    rule_set = _rule_set_or_404(db, rule_set_id)
    rules = ruleset_service.collect_rules(db, rule_set.id)
    for rule in rules:
        if not rule["pattern"] and not rule["keywords"]:
            rule["field_only"] = True
    return {"items": rules, "total": len(rules)}


@router.post("/rulesets/{rule_set_id}/rules/import")
def import_rules(rule_set_id: int, db: Session = Depends(get_db)) -> dict:
    rule_set = _rule_set_or_404(db, rule_set_id)
    added = ruleset_service.import_working_rules(db, rule_set)
    db.commit()
    return {"added": added, "total": len(ruleset_service.collect_rules(db, rule_set.id))}


@router.get("/rulesets/{rule_set_id}/versions")
def list_versions(rule_set_id: int, db: Session = Depends(get_db)) -> dict:
    rule_set = _rule_set_or_404(db, rule_set_id)
    rows = db.scalars(select(RuleSetVersion).where(RuleSetVersion.rule_set_id == rule_set.id)
                      .order_by(RuleSetVersion.id.desc())).all()
    return {"items": [_version_summary(row) for row in rows], "total": len(rows),
            "active_version": (ruleset_service.active_version(db, rule_set) or RuleSetVersion()).version if rows else ""}


@router.post("/rulesets/{rule_set_id}/versions")
def publish_version(rule_set_id: int, payload: PublishPayload, request: Request,
                    db: Session = Depends(get_db)) -> dict:
    rule_set = _rule_set_or_404(db, rule_set_id)
    rules = [rule.model_dump() for rule in payload.rules] if payload.rules is not None else None
    try:
        row = ruleset_service.publish(db, rule_set, version=payload.version, changelog=payload.changelog,
                                      min_agent_version=payload.min_agent_version, rules=rules,
                                      published_by=_actor(db, request))
    except RuleSetError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    db.commit()
    return _version_summary(row)


@router.post("/rulesets/{rule_set_id}/rollback")
def rollback_version(rule_set_id: int, payload: RollbackPayload, request: Request,
                     db: Session = Depends(get_db)) -> dict:
    rule_set = _rule_set_or_404(db, rule_set_id)
    try:
        row = ruleset_service.rollback(db, rule_set, to_version=payload.to_version,
                                       changelog=payload.changelog, published_by=_actor(db, request))
    except RuleSetError as exc:
        db.rollback()
        raise HTTPException(400, str(exc)) from exc
    db.commit()
    return _version_summary(row)


@router.get("/probes/{probe_id}/ruleset/manifest")
def probe_ruleset_manifest(probe_id: int, request: Request, current: str = Query(default=""),
                           db: Session = Depends(get_db)) -> dict:
    """Cheap check a probe performs before downloading anything."""
    authenticated_probe(probe_id, request, db)
    ruleset_service.ensure_baseline(db)
    db.commit()
    rule_set, row = ruleset_service.resolve_for_probe(db)
    return {
        "rule_set": rule_set.name,
        "active_version": row.version,
        "up_to_date": bool(current) and current == row.version,
        "manifest": ruleset_service.version_manifest(
            db, row, download_path=f"/api/v1/probes/{probe_id}/ruleset?version={row.version}"),
        "capabilities": ruleset_service.capabilities(),
    }


@router.get("/probes/{probe_id}/ruleset")
def probe_ruleset_download(probe_id: int, request: Request, version: str = Query(default=""),
                           agent_version: str = Header(default="", alias="X-Agent-Version"),
                           db: Session = Depends(get_db)) -> Response:
    """The exact published bytes, with the digest of those bytes in the headers."""
    authenticated_probe(probe_id, request, db)
    rule_set, active = ruleset_service.resolve_for_probe(db)
    if version:
        row = db.scalar(select(RuleSetVersion).where(RuleSetVersion.rule_set_id == rule_set.id,
                                                    RuleSetVersion.version == version))
        if row is None:
            raise HTTPException(404, f"规则版本 {version} 不存在")
    else:
        row = active
    if row.min_agent_version and agent_version:
        from shared.sensitive_detection.ruleset import satisfies_minimum

        if not satisfies_minimum(agent_version, row.min_agent_version):
            raise HTTPException(409, f"探针版本 {agent_version} 低于该规则包要求的最小版本 {row.min_agent_version}")
    payload = row.package or b""
    if not payload:
        raise HTTPException(500, "规则版本内容缺失")
    return Response(content=payload, media_type="application/json", headers={
        "X-RuleSet-Version": row.version,
        "X-RuleSet-Sha256": row.sha256,
        "X-RuleSet-RuleCount": str(row.rule_count),
        "Content-Disposition": f'attachment; filename="ruleset-{row.version}.json"',
    })
