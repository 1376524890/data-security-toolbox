"""Policy groups: the reusable rule bundle an operator selects at task dispatch.

A group references rule identifiers (from the shared rule library) plus extra
categories/keywords and thresholds. It never copies rule content, so the rule
library stays the single source of truth for what a rule *is*; a group only
decides which of those rules a scan should enforce, and a queued task stores the
resolved snapshot so editing a group later cannot change work already handed out.
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import PolicyGroup


class PolicyGroupError(ValueError):
    """The group cannot be stored or turned into a dispatch snapshot."""


_SHA256 = re.compile(r"^[a-f0-9]{64}$")


#: Where a group may apply; anything else is rejected instead of silently ignored.
SCOPES = ("file", "network", "database")

MIN_CONFIDENCE_FLOOR = 0.0
MIN_CONFIDENCE_CEILING = 1.0
MIN_MATCHES_FLOOR = 1
MIN_MATCHES_CEILING = 10_000
MAX_RULE_IDS = 512
MAX_TERMS = 256


def _clean_terms(values: Any, *, field: str, limit: int) -> list[str]:
    if not isinstance(values, list):
        raise PolicyGroupError(f"{field} 必须是数组")
    items = [str(item).strip() for item in values if str(item).strip()]
    for item in items:
        if len(item) > 200:
            raise PolicyGroupError(f"{field} 单项不得超过 200 字符")
    return list(dict.fromkeys(items))[:limit]


def validate(values: dict[str, Any]) -> dict[str, Any]:
    """Type- and range-check the supplied fields; unknown keys are rejected."""
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if key in {"name", "description"}:
            cleaned[key] = str(value)[:512]
        elif key == "enabled":
            cleaned[key] = bool(value)
        elif key == "scope":
            scopes = _clean_terms(value, field="scope", limit=len(SCOPES))
            unknown = [item for item in scopes if item not in SCOPES]
            if unknown:
                raise PolicyGroupError(f"scope 只允许 {', '.join(SCOPES)}：{', '.join(unknown)}")
            cleaned[key] = scopes
        elif key == "rule_ids":
            cleaned[key] = _clean_terms(value, field="rule_ids", limit=MAX_RULE_IDS)
        elif key == "categories":
            cleaned[key] = _clean_terms(value, field="categories", limit=MAX_TERMS)
        elif key == "keywords":
            cleaned[key] = _clean_terms(value, field="keywords", limit=MAX_TERMS)
        elif key == "fingerprints":
            items = _clean_terms(value, field="fingerprints", limit=MAX_RULE_IDS)
            bad = [item for item in items if not _SHA256.match(item.lower())]
            if bad:
                raise PolicyGroupError(f"fingerprints 必须是 SHA256：{', '.join(bad[:3])}")
            cleaned[key] = [item.lower() for item in items]
        elif key == "min_confidence":
            try:
                number = float(value)
            except (TypeError, ValueError) as exc:
                raise PolicyGroupError("min_confidence 必须是数字") from exc
            if number < MIN_CONFIDENCE_FLOOR or number > MIN_CONFIDENCE_CEILING:
                raise PolicyGroupError("min_confidence 必须在 0 与 1 之间")
            cleaned[key] = number
        elif key == "min_matches":
            try:
                number = int(value)
            except (TypeError, ValueError) as exc:
                raise PolicyGroupError("min_matches 必须是整数") from exc
            if number < MIN_MATCHES_FLOOR or number > MIN_MATCHES_CEILING:
                raise PolicyGroupError(
                    f"min_matches 必须在 {MIN_MATCHES_FLOOR} 与 {MIN_MATCHES_CEILING} 之间")
            cleaned[key] = number
        else:
            raise PolicyGroupError(f"未知字段: {key}")
    return cleaned


def serialize(group: PolicyGroup) -> dict[str, Any]:
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "enabled": bool(group.enabled),
        "version": int(group.version or 1),
        "scope": list(group.scope or []),
        "rule_ids": list(group.rule_ids or []),
        "categories": list(group.categories or []),
        "keywords": list(group.keywords or []),
        "fingerprints": list(group.fingerprints or []),
        "min_confidence": float(group.min_confidence or 0.0),
        "min_matches": int(group.min_matches or 1),
        "created_by": group.created_by,
        "created_at": group.created_at.isoformat() if group.created_at else "",
        "updated_at": group.updated_at.isoformat() if group.updated_at else "",
    }


def apply_values(group: PolicyGroup, values: dict[str, Any]) -> PolicyGroup:
    for key, value in values.items():
        setattr(group, key, value)
    return group


def get_or_404(db: Session, group_id: int) -> PolicyGroup:
    group = db.get(PolicyGroup, group_id)
    if group is None:
        raise PolicyGroupError(f"策略组 {group_id} 不存在")
    return group


def network_rule_overlay(db: Session) -> dict[str, list[str]]:
    """The rules enabled, network-scoped policy groups add to the passive DLP stage.

    The file scan and the network stage have to enforce the same rules: a
    fingerprint an operator accepted from a file scan is a statement about that
    content wherever it shows up, traffic included. Until this existed, an
    accepted hash only ever reached the file side and the network side kept
    running its own separate fingerprint list, which is exactly how the two
    halves drifted.

    Only enabled groups whose scope names ``network`` contribute, so a group an
    operator scoped to files keeps governing files alone. Analyst-authored rules
    (``rule_ids``) need no copy here: the rule store is global and every stage
    already scans with it.
    """
    fingerprints: list[str] = []
    keywords: list[str] = []
    categories: list[str] = []
    for group in db.scalars(select(PolicyGroup).where(PolicyGroup.enabled.is_(True))).all():
        if "network" not in (group.scope or []):
            continue
        fingerprints.extend(str(item).lower() for item in (group.fingerprints or []))
        keywords.extend(str(item) for item in (group.keywords or []))
        categories.extend(str(item) for item in (group.categories or []))
    return {
        "fingerprints": list(dict.fromkeys(item for item in fingerprints if _SHA256.match(item))),
        "keywords": list(dict.fromkeys(item for item in keywords if item.strip())),
        "categories": list(dict.fromkeys(item for item in categories if item.strip())),
    }


def merge_network_rules(policy: dict[str, Any], overlay: dict[str, list[str]]) -> dict[str, Any]:
    """Fold the group overlay into a DLP policy without dropping what it had."""
    merged = dict(policy)
    for key in ("fingerprints", "keywords", "categories"):
        current = [str(item) for item in (merged.get(key) or [])]
        merged[key] = list(dict.fromkeys([*current, *overlay.get(key, [])]))
    return merged
