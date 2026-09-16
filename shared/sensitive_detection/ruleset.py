"""Rule pack loading, validation and versioning.

A published pack is data: ``{"schema_version", "ruleset_version", "engine_version",
"min_agent_version", "rules": [...]}``. Loading never executes anything from the
pack and never fetches a URL - the caller supplies the already-downloaded bytes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .engine import ENGINE_VERSION, SCHEMA_VERSION, SensitiveDetectionEngine
from .rules import builtin_rules


class RulePackError(ValueError):
    """The pack is unusable; the caller keeps its previous rules."""


@dataclass(slots=True)
class RulePack:
    ruleset_version: str
    rules: list[dict[str, Any]] = field(default_factory=list)
    engine_version: str = ENGINE_VERSION
    min_agent_version: str = ""
    schema_version: str = SCHEMA_VERSION
    created_at: str = ""
    sha256: str = ""
    rule_count: int = 0
    source: str = "builtin"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "ruleset_version": self.ruleset_version,
            "engine_version": self.engine_version,
            "min_agent_version": self.min_agent_version,
            "created_at": self.created_at,
            "sha256": self.sha256,
            "rule_count": self.rule_count or len(self.rules),
            "source": self.source,
        }


def version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in str(value or "").split("."):
        digits = "".join(character for character in chunk if character.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def satisfies_minimum(version: str, minimum: str) -> bool:
    """True when ``version`` >= ``minimum``. An empty minimum always passes."""
    if not minimum:
        return True
    return version_tuple(version) >= version_tuple(minimum)


def pack_digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def load_rule_pack(payload: bytes, *, agent_version: str = "", expected_sha256: str = "") -> RulePack:
    """Parse and validate a rule pack; raise :class:`RulePackError` on any doubt."""
    if expected_sha256 and pack_digest(payload).lower() != str(expected_sha256).lower():
        raise RulePackError("digest_mismatch")
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RulePackError("invalid_json") from exc
    if not isinstance(document, dict):
        raise RulePackError("pack_not_object")
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RulePackError("pack_without_rules")
    engine_version = str(document.get("engine_version") or ENGINE_VERSION)
    if version_tuple(engine_version)[:2] != version_tuple(ENGINE_VERSION)[:2]:
        raise RulePackError("engine_version_incompatible")
    minimum = str(document.get("min_agent_version") or "")
    if agent_version and not satisfies_minimum(agent_version, minimum):
        raise RulePackError("agent_version_too_old")
    engine = SensitiveDetectionEngine(rules)
    if not engine.rules:
        raise RulePackError("no_usable_rules")
    return RulePack(
        ruleset_version=str(document.get("ruleset_version") or ""),
        rules=[rule for rule in engine.rules],
        engine_version=engine_version,
        min_agent_version=minimum,
        schema_version=str(document.get("schema_version") or SCHEMA_VERSION),
        created_at=str(document.get("created_at") or ""),
        sha256=pack_digest(payload),
        rule_count=len(engine.rules),
        source=str(document.get("source") or "published"),
    )


def build_local_pack(version: str = "builtin-1") -> RulePack:
    """The in-package baseline snapshot used when a probe has never synced."""
    rules = builtin_rules()
    payload = json.dumps({"ruleset_version": version, "rules": rules}, ensure_ascii=False).encode("utf-8")
    return RulePack(ruleset_version=version, rules=rules, sha256=pack_digest(payload),
                    rule_count=len(rules), source="builtin")
