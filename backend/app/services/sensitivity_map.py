"""Central, explainable L1..L4 data-classification mapping.

L1..L4 classifies *data*; Critical/High/Medium/Low is the risk severity the
existing pages filter on. They are two different axes, so this module is the one
place that relates them: nothing here writes to a stored ``sensitivity`` column,
and an override never rewrites history.

The defaults live in the shared package (``shared.sensitive_detection.entities``)
because the probe classifies with the same table. An operator may override
individual categories through a ``SystemSetting`` row named
``sensitivity_levels`` holding e.g. ``{"ID_CARD": "L4"}``; unresolved categories
fall back to the shipped default and the explanation says which one applied.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.services import sensitive_engine as engine

LEVELS = engine.shared_entities.LEVELS

#: Human-readable meaning, shown next to the bare code in the UI.
LEVEL_META: dict[str, dict[str, str]] = {
    "L4": {"name": "核心/极高敏感", "description": "凭证、密钥、令牌等一旦泄露可直接造成系统失陷的数据"},
    "L3": {"name": "高敏感个人信息", "description": "身份证、银行卡、医疗记录等强标识或强金融属性的数据"},
    "L2": {"name": "一般个人信息/重要业务数据", "description": "手机号、邮箱、地址等可识别到个人的数据"},
    "L1": {"name": "低敏感/公开", "description": "姓名、用户标识等单独不足以识别个人的数据"},
}

LEVEL_SETTING = "sensitivity_levels"

#: Infrastructure metadata: it may be evidence for a transfer, but it must never
#: be the reason a file, sheet or column is called sensitive.
NON_PROTECTED = {"IP_ADDRESS", "MAC_ADDRESS", "DATE_TIME", "URL", "NRP", "LOCATION", "DOMAIN"}


def overrides(db: Session | None) -> dict[str, str]:
    """Operator overrides from ``SystemSetting``; an unreadable row is ignored."""
    if db is None:
        return {}
    from app.models import SystemSetting

    try:
        row = db.scalar(select(SystemSetting).where(SystemSetting.key == LEVEL_SETTING))
    except Exception:  # pragma: no cover - a broken settings table must not break a page
        return {}
    payload = (row.value if row else None) or {}
    if not isinstance(payload, dict):
        return {}
    return {str(key).upper(): str(value).upper() for key, value in payload.items()
            if str(value).upper() in LEVELS}


def is_protected(category: object) -> bool:
    """False for structure-only categories such as IP addresses and timestamps."""
    canonical = engine.canonical_entity(category)
    return canonical not in NON_PROTECTED and canonical not in engine.shared_entities.STRUCTURAL_ENTITIES


def level_for(category: object, *, mapping: dict[str, str] | None = None) -> str:
    canonical = engine.canonical_entity(category)
    if mapping and canonical in mapping:
        return mapping[canonical]
    return engine.level_of(category)


def severity_for(category: object, *, mapping: dict[str, str] | None = None) -> str:
    canonical = engine.canonical_entity(category)
    if mapping and canonical in mapping:
        return engine.severity_of_level(mapping[canonical])
    return engine.severity_of(category)


def explain(category: object, *, mapping: dict[str, str] | None = None) -> dict[str, Any]:
    """Why this category got this level, so a page can show the reasoning."""
    canonical = engine.canonical_entity(category)
    overridden = bool(mapping and canonical in mapping)
    level = level_for(category, mapping=mapping)
    meta = LEVEL_META.get(level, {})
    return {
        "category": engine.legacy_name(category) or canonical.lower(),
        "entity": canonical,
        "level": level,
        "level_name": meta.get("name", ""),
        "level_description": meta.get("description", ""),
        "severity": severity_for(category, mapping=mapping),
        "protected": is_protected(category),
        "source": "settings_override" if overridden else "builtin_default",
        "field_only": engine.is_field_only(category),
    }


def worst_level(categories: Any, *, mapping: dict[str, str] | None = None) -> str:
    """Highest (most sensitive) level of a set; ``L1`` for an empty set."""
    best = "L1"
    for category in categories or []:
        level = level_for(category, mapping=mapping)
        if LEVELS.index(level) > LEVELS.index(best):
            best = level
    return best


def worst_severity(categories: Any, *, mapping: dict[str, str] | None = None) -> str:
    return engine.severity_of_level(worst_level(categories, mapping=mapping))


def catalog(mapping: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Every built-in category with its effective classification."""
    return [explain(entity, mapping=mapping) for entity in engine.known_entities()]


def non_protected_catalog() -> list[dict[str, Any]]:
    """Entities that are reported but can never make data sensitive.

    Published explicitly so a page can explain why an IP address in a file did not
    raise the file's level, instead of leaving the operator to guess.
    """
    return [explain(entity) for entity in sorted(engine.shared_entities.STRUCTURAL_ENTITIES)]


__all__ = ["LEVELS", "LEVEL_META", "LEVEL_SETTING", "NON_PROTECTED", "catalog", "explain",
           "is_protected", "level_for", "non_protected_catalog", "overrides", "severity_for",
           "worst_level", "worst_severity"]