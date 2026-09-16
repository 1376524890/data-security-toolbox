"""Central rule sets: one editable working copy, immutable published versions.

The server is the only place rules are managed. A published version is stored as
the exact bytes a probe downloads, so:

* editing the working copy never changes what an existing version contains;
* a rollback publishes the old content as a *new* version instead of overwriting
  history, and the rollback itself is traceable;
* the SHA256 in the manifest is a digest of those stored bytes, not of a
  re-serialised copy of the rules.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Rule, RuleSet, RuleSetVersion
from app.services import sensitive_engine
from app.services.rule_library import managed_rules

from shared.sensitive_detection.engine import ENGINE_VERSION, SCHEMA_VERSION  # noqa: E402
from shared.sensitive_detection.entities import canonical_entity, level_of  # noqa: E402
from shared.sensitive_detection.ruleset import load_rule_pack, pack_digest  # noqa: E402

DEFAULT_RULE_SET = "default"
BASELINE_VERSION = "builtin-1"
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# A probe downloads this in one bounded request; anything larger is a mistake.
MAX_PACK_BYTES = 2 * 1024 * 1024
MAX_RULES_PER_PACK = 2000

# Legacy store source names mapped onto the closed provenance set.
_SOURCE_BY_LEGACY = {"presidio": "presidio_static", "manual": "manual", "builtin": "builtin"}


class RuleSetError(ValueError):
    """The request cannot produce a usable, immutable version."""


def _legacy_source(value: object) -> str:
    return _SOURCE_BY_LEGACY.get(str(value or "").strip().lower(), "manual")


def serialize_rule(rule: Rule) -> dict[str, Any]:
    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "entity": rule.entity,
        "pattern": rule.pattern or "",
        "confidence": float(rule.confidence),
        "validator": rule.validator or "",
        "field_hints": list(rule.field_hints or []),
        "keywords": list(rule.keywords or []),
        "enabled": bool(rule.enabled),
        "rule_source": rule.source or "builtin",
        "level": level_of(rule.entity),
        "description": rule.description or "",
    }


def rule_payload(value: dict[str, Any], *, source: str = "manual") -> dict[str, Any]:
    """Normalise an API/caller supplied rule into the pack format."""
    rule_id = str(value.get("rule_id") or value.get("id") or "").strip()
    if not rule_id or len(rule_id) > 128:
        raise RuleSetError("rule_id 必填且不超过 128 字符")
    entity = canonical_entity(value.get("entity") or rule_id)
    return {
        "rule_id": rule_id,
        "name": str(value.get("name") or rule_id)[:255],
        "entity": entity,
        "pattern": str(value.get("pattern") or ""),
        "confidence": float(value.get("confidence") or 0.5),
        "validator": str(value.get("validator") or ""),
        "field_hints": [str(item) for item in (value.get("field_hints") or [])],
        "keywords": [str(item) for item in (value.get("keywords") or [])],
        "enabled": bool(value.get("enabled", True)),
        "rule_source": str(value.get("rule_source") or value.get("source") or source),
        "level": str(value.get("level") or level_of(entity)),
        "description": str(value.get("description") or "")[:2000],
    }


def collect_rules(db: Session, rule_set_id: int, *, include_disabled: bool = True) -> list[dict[str, Any]]:
    rows = db.scalars(select(Rule).where(Rule.rule_set_id == rule_set_id).order_by(Rule.rule_id)).all()
    rules = [serialize_rule(row) for row in rows]
    return rules if include_disabled else [rule for rule in rules if rule["enabled"]]


def build_pack(rules: Iterable[dict[str, Any]], version: str, *, min_agent_version: str = "",
               created_at: str = "") -> tuple[bytes, list[dict[str, Any]]]:
    """Validate the rules and return the exact publishable bytes.

    Validation is real: the pack is loaded, an engine is built from it and any
    unusable rule makes the whole publish fail instead of being silently dropped.
    """
    if not VERSION_PATTERN.match(version or ""):
        raise RuleSetError("版本号只允许字母、数字、点、下划线和短横线，长度 1-64")
    prepared = [rule_payload(rule, source=str(rule.get("rule_source") or "manual")) for rule in rules]
    if not prepared:
        raise RuleSetError("规则集不能为空")
    if len(prepared) > MAX_RULES_PER_PACK:
        raise RuleSetError(f"规则数超过上限 {MAX_RULES_PER_PACK}")
    seen: set[str] = set()
    for rule in prepared:
        if rule["rule_id"] in seen:
            raise RuleSetError(f"规则 ID 重复: {rule['rule_id']}")
        seen.add(rule["rule_id"])
    document = {
        "schema_version": SCHEMA_VERSION,
        "ruleset_version": version,
        "engine_version": ENGINE_VERSION,
        "min_agent_version": min_agent_version or "",
        "created_at": created_at or datetime.now(UTC).isoformat(),
        "rules": prepared,
    }
    payload = json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(payload) > MAX_PACK_BYTES:
        raise RuleSetError(f"规则包超过上限 {MAX_PACK_BYTES} 字节")
    try:
        pack = load_rule_pack(payload)
    except Exception as exc:  # RulePackError and any json/engine failure
        raise RuleSetError(f"规则包校验失败: {exc}") from exc
    if pack.rule_count != len(prepared):
        rejected = [rule["rule_id"] for rule in prepared if rule["rule_id"] not in
                    {item["rule_id"] for item in pack.rules}]
        raise RuleSetError(f"规则不可用: {', '.join(sorted(rejected))}")
    if not any(rule["enabled"] for rule in prepared):
        raise RuleSetError("规则集至少要有一条启用的规则")
    return payload, prepared


def get_or_create_rule_set(db: Session, name: str = DEFAULT_RULE_SET, description: str = "") -> RuleSet:
    rule_set = db.scalar(select(RuleSet).where(RuleSet.name == name))
    if rule_set is None:
        rule_set = RuleSet(name=name, description=description or "内置与人工维护的检测规则")
        db.add(rule_set)
        db.flush()
    return rule_set


def import_working_rules(db: Session, rule_set: RuleSet) -> int:
    """Seed the working copy from builtin + legacy managed rules.

    Existing working rules keep their analyst edits; only missing IDs are added.
    """
    existing = {row.rule_id for row in db.scalars(select(Rule).where(Rule.rule_set_id == rule_set.id))}
    added = 0
    candidates: list[dict[str, Any]] = []
    for rule in sensitive_engine.get_engine().rules:
        candidates.append({**rule, "rule_source": "builtin"})
    for rule in managed_rules():
        candidates.append({
            "rule_id": str(rule.get("id") or ""),
            "name": rule.get("name") or "",
            "entity": rule.get("entity") or rule.get("name") or "",
            "pattern": rule.get("pattern") or "",
            "confidence": rule.get("confidence"),
            "field_hints": rule.get("field_hints") or [],
            "keywords": rule.get("keywords") or [],
            "enabled": rule.get("enabled", True),
            "rule_source": _legacy_source(rule.get("source")),
            "description": rule.get("recognizer") or "",
        })
    for candidate in candidates:
        try:
            payload = rule_payload(candidate, source=str(candidate.get("rule_source") or "builtin"))
        except RuleSetError:
            continue
        if payload["rule_id"] in existing:
            continue
        db.add(Rule(
            rule_set_id=rule_set.id, rule_id=payload["rule_id"], name=payload["name"], entity=payload["entity"],
            pattern=payload["pattern"], confidence=payload["confidence"], validator=payload["validator"],
            field_hints=payload["field_hints"], keywords=payload["keywords"], enabled=payload["enabled"],
            source=payload["rule_source"], description=payload["description"],
        ))
        existing.add(payload["rule_id"])
        added += 1
    db.flush()
    return added


def active_version(db: Session, rule_set: RuleSet) -> RuleSetVersion | None:
    if not rule_set.active_version_id:
        return None
    return db.get(RuleSetVersion, rule_set.active_version_id)


def publish(db: Session, rule_set: RuleSet, *, version: str, published_by: str = "", changelog: str = "",
            min_agent_version: str = "", rules: list[dict[str, Any]] | None = None,
            origin_version: str = "") -> RuleSetVersion:
    """Publish an immutable version and make it active."""
    if db.scalar(select(RuleSetVersion).where(RuleSetVersion.rule_set_id == rule_set.id,
                                             RuleSetVersion.version == version)):
        raise RuleSetError(f"版本 {version} 已存在，已发布的版本不可覆盖")
    source_rules = rules if rules is not None else collect_rules(db, rule_set.id)
    payload, prepared = build_pack(source_rules, version, min_agent_version=min_agent_version)
    digest = pack_digest(payload)
    created_at = datetime.now(UTC)
    row = RuleSetVersion(
        rule_set_id=rule_set.id, version=version, status="published", schema_version=SCHEMA_VERSION,
        engine_version=ENGINE_VERSION, min_agent_version=min_agent_version or "", sha256=digest,
        rule_count=len(prepared), origin_version=origin_version or "", changelog=changelog[:512],
        published_by=published_by[:128], package=payload,
        manifest=manifest_for(version, digest, len(prepared), min_agent_version, created_at),
    )
    db.add(row)
    db.flush()
    for other in db.scalars(select(RuleSetVersion).where(RuleSetVersion.rule_set_id == rule_set.id,
                                                       RuleSetVersion.id != row.id,
                                                       RuleSetVersion.status == "published")):
        other.status = "superseded"
    rule_set.active_version_id = row.id
    db.flush()
    return row


def manifest_for(version: str, digest: str, rule_count: int, min_agent_version: str,
                 created_at: datetime | None = None, *, download_path: str = "") -> dict[str, Any]:
    return {
        "ruleset_version": version,
        "schema_version": SCHEMA_VERSION,
        "engine_version": ENGINE_VERSION,
        "min_agent_version": min_agent_version or "",
        "created_at": (created_at or datetime.now(UTC)).isoformat(),
        "sha256": digest,
        "rule_count": rule_count,
        "size": None,  # filled with the stored byte length; kept explicit, never guessed
        "download_path": download_path,
    }


def version_manifest(db: Session, row: RuleSetVersion, *, download_path: str = "") -> dict[str, Any]:
    manifest = dict(row.manifest or {})
    manifest.update({
        "ruleset_version": row.version,
        "sha256": row.sha256,
        "rule_count": row.rule_count,
        "size": len(row.package or b""),
        "download_path": download_path or f"/api/v1/probes/{{probe_id}}/ruleset?version={row.version}",
    })
    return manifest


def rollback(db: Session, rule_set: RuleSet, *, to_version: str, published_by: str = "",
             changelog: str = "") -> RuleSetVersion:
    """Republish an earlier version's rules as a new, traceable version.

    The rules are re-serialised rather than copied byte for byte: the pack embeds
    its own ``ruleset_version``, and a probe that recorded the old label while
    downloading the new one could not be reconciled with the manifest. History is
    still intact - the original row keeps its original bytes.
    """
    target = db.scalar(select(RuleSetVersion).where(RuleSetVersion.rule_set_id == rule_set.id,
                                                   RuleSetVersion.version == to_version))
    if target is None:
        raise RuleSetError(f"版本 {to_version} 不存在")
    document = json.loads(target.package.decode("utf-8"))
    new_version = _next_rollback_version(db, rule_set, to_version)
    payload, prepared = build_pack(document.get("rules") or [], new_version,
                                   min_agent_version=target.min_agent_version or "")
    digest = pack_digest(payload)
    created_at = datetime.now(UTC)
    row = RuleSetVersion(
        rule_set_id=rule_set.id, version=new_version, status="published", schema_version=target.schema_version,
        engine_version=target.engine_version, min_agent_version=target.min_agent_version or "", sha256=digest,
        rule_count=len(prepared), origin_version=to_version,
        changelog=(changelog or f"回滚到 {to_version}")[:512], published_by=published_by[:128],
        package=payload, manifest=manifest_for(new_version, digest, len(prepared),
                                               target.min_agent_version, created_at),
    )
    db.add(row)
    db.flush()
    for other in db.scalars(select(RuleSetVersion).where(RuleSetVersion.rule_set_id == rule_set.id,
                                                       RuleSetVersion.id != row.id,
                                                       RuleSetVersion.status == "published")):
        other.status = "superseded"
    rule_set.active_version_id = row.id
    db.flush()
    return row


def _next_rollback_version(db: Session, rule_set: RuleSet, target: str) -> str:
    base = f"{target}.rollback"
    existing = {row.version for row in db.scalars(select(RuleSetVersion).where(RuleSetVersion.rule_set_id == rule_set.id))}
    if base not in existing:
        return base
    index = 2
    while f"{base}{index}" in existing:
        index += 1
    return f"{base}{index}"


def ensure_baseline(db: Session) -> RuleSet:
    """Idempotently import the working copy and publish the builtin snapshot."""
    rule_set = get_or_create_rule_set(db)
    import_working_rules(db, rule_set)
    if active_version(db, rule_set) is None:
        publish(db, rule_set, version=BASELINE_VERSION, published_by="system",
                changelog="内置规则基线快照（随包发布的初始版本）")
    db.flush()
    return rule_set


def resolve_for_probe(db: Session) -> tuple[RuleSet, RuleSetVersion]:
    rule_set = ensure_baseline(db)
    row = active_version(db, rule_set)
    if row is None:
        raise RuleSetError("没有可用的已发布规则版本")
    return rule_set, row


def capabilities() -> dict[str, Any]:
    """What the platform can negotiate, reported to probes on heartbeat."""
    return {
        "rulesets": True,
        "schema_version": SCHEMA_VERSION,
        "engine_version": ENGINE_VERSION,
        "max_pack_bytes": MAX_PACK_BYTES,
        "digest": "sha256",
    }


def digest_of(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
