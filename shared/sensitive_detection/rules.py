"""Rule declarations for the built-in P0 entity set.

Rules are plain JSON-serialisable data: a rule pack published by the platform in
stage 2 uses exactly this shape, and a rule may only reference validators by name
from :mod:`shared.sensitive_detection.validators`.
"""
from __future__ import annotations

from typing import Any

from .entities import (
    ADDRESS,
    API_KEY,
    BANK_CARD,
    CREDENTIAL,
    EMAIL,
    ID_CARD,
    MEDICAL_RECORD,
    NAME,
    PHONE,
    TOKEN,
    USER_ID,
)
from . import confidence as confidence_module

# Rule fields, used by the validator so a malformed pack fails loudly.
RULE_FIELDS = (
    "rule_id",
    "name",
    "entity",
    "pattern",
    "enabled",
    "confidence",
    "validator",
    "rule_source",
    "field_hints",
    "keywords",
    "sheet_hints",
    "recognizer",
    "level",
    "description",
)

BUILTIN_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "SD_PHONE_001",
        "name": "中国大陆手机号",
        "entity": PHONE,
        "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)",
        "confidence": 0.7,
        "validator": "cn_mobile",
        "field_hints": ["phone", "mobile", "cellphone", "tel", "手机", "联系电话", "联系方式"],
        "keywords": ["手机号", "手机号码"],
        "description": "11 位大陆手机号；格式正确即成立，字段名可加强上下文。",
    },
    {
        "rule_id": "SD_ID_CARD_001",
        "name": "身份证号",
        "entity": ID_CARD,
        "pattern": r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)",
        "confidence": 0.9,
        "validator": "cn_id_card",
        "field_hints": ["id_card", "idcard", "identity", "证件", "身份证", "证件号码"],
        "keywords": ["身份证号", "身份证号码"],
        "description": "18 位身份证；校验位与出生日期作为证据，格式正确但不合法时降为 0.7。",
    },
    {
        "rule_id": "SD_BANK_CARD_001",
        "name": "银行卡号",
        "entity": BANK_CARD,
        "pattern": r"(?<!\d)(?:62|4\d{3}|5[1-5]\d{2})[ -]?(?:\d[ -]?){12,17}(?!\d)",
        "confidence": 0.85,
        "validator": "luhn",
        "field_hints": ["bank_card", "card_no", "cardno", "银行卡", "卡号", "账号"],
        "keywords": ["银行卡号"],
        "description": "Luhn 通过为 0.9，未通过降为 0.45（低于告警阈值，仅作证据）。",
    },
    {
        "rule_id": "SD_EMAIL_001",
        "name": "邮箱地址",
        "entity": EMAIL,
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "confidence": 0.85,
        "validator": "email_shape",
        "field_hints": ["email", "mail", "邮箱", "电子邮件"],
        "keywords": ["邮箱地址"],
        "description": "硬校验：拒绝数据库连接串里的 user@host。",
    },
    {
        "rule_id": "SD_API_KEY_001",
        "name": "API Key / Secret",
        "entity": API_KEY,
        "pattern": r"\b(?:AKIA|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{20,})\b",
        "confidence": 0.95,
        "validator": "",
        "field_hints": ["api_key", "apikey", "secret", "密钥", "access_key"],
        "keywords": ["api key", "apikey", "secret key"],
        "description": "已知前缀的云厂商/平台密钥。",
    },
    {
        "rule_id": "SD_TOKEN_001",
        "name": "长随机串（疑似 Token）",
        "entity": TOKEN,
        "pattern": r"\b(?:Bearer\s+)?[A-Za-z0-9_\-]{32,}\b",
        "confidence": 0.3,
        "validator": "",
        "field_hints": ["token", "bearer", "令牌", "访问令牌"],
        "keywords": ["bearer "],
        "description": "独立不足以告警：哈希、base64、容器 ID 都会命中。",
    },
    {
        "rule_id": "SD_CREDENTIAL_001",
        "name": "口令/密钥字段",
        "entity": CREDENTIAL,
        "pattern": r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*\S{6,}",
        "confidence": 0.85,
        "validator": "",
        "field_hints": ["password", "passwd", "secret", "credential", "口令", "密码"],
        "keywords": ["password=", "passwd=", "secret="],
        "description": "赋值形态的口令字段；只上报字段与计数，不上报取值。",
    },
    {
        "rule_id": "SD_NAME_001",
        "name": "姓名（仅字段/上下文）",
        "entity": NAME,
        "pattern": "",
        "confidence": confidence_module.FIELD_ONLY_CONFIDENCE,
        "validator": "",
        "field_hints": ["name", "fullname", "姓名", "联系人"],
        "keywords": [],
        "description": "P0 无 NER：只有字段名证据，明确低置信度。",
    },
    {
        "rule_id": "SD_ADDRESS_001",
        "name": "地址（仅字段/上下文）",
        "entity": ADDRESS,
        "pattern": "",
        "confidence": confidence_module.FIELD_ONLY_CONFIDENCE,
        "validator": "",
        "field_hints": ["address", "addr", "地址", "住址", "通信地址"],
        "keywords": [],
        "description": "P0 无 NER：只有字段名证据，明确低置信度。",
    },
    {
        "rule_id": "SD_USER_ID_001",
        "name": "用户标识（仅字段/上下文）",
        "entity": USER_ID,
        "pattern": "",
        "confidence": 0.3,
        "validator": "",
        "field_hints": ["user_id", "userid", "uid", "account", "账号"],
        "keywords": [],
        "description": "账号标识本身不是敏感数据，仅作为列的上下文。",
    },
    {
        "rule_id": "SD_MEDICAL_001",
        "name": "医疗记录（仅字段/上下文）",
        "entity": MEDICAL_RECORD,
        "pattern": "",
        "confidence": confidence_module.FIELD_ONLY_CONFIDENCE,
        "validator": "",
        "field_hints": ["medical", "patient", "diagnosis", "病历", "诊断", "就诊"],
        "keywords": ["病历", "诊断"],
        "description": "P0 无 NER：仅有字段/上下文证据，不得冒充已完成识别。",
    },
    {
        "rule_id": "SD_MEDICAL_002",
        "name": "医疗记录上下文词",
        "entity": MEDICAL_RECORD,
        "pattern": r"(?i)(?:病历号|病历|诊断|处方|住院号|patient\s*id|medical\s*record|icd[-_\s]?10)",
        "confidence": 0.45,
        "validator": "",
        "field_hints": [],
        "keywords": [],
        "description": "出现在文本中的医疗术语；置信度低于告警阈值，只作上下文证据。",
    },
]


def builtin_rules() -> list[dict[str, Any]]:
    """Deep-enough copy so callers cannot mutate the shared declarations."""
    return [dict(rule) for rule in BUILTIN_RULES]


def normalize_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Fill defaults so built-in and published rules behave identically."""
    normalized = {key: rule.get(key) for key in RULE_FIELDS if key in rule}
    normalized.setdefault("rule_id", str(rule.get("id") or rule.get("rule_id") or ""))
    normalized.setdefault("name", normalized["rule_id"])
    normalized.setdefault("entity", normalized["rule_id"] or "UNKNOWN")
    normalized.setdefault("pattern", "")
    normalized.setdefault("enabled", True)
    normalized.setdefault("rule_source", str(rule.get("source") or "builtin"))
    normalized["confidence"] = confidence_module.clamp(normalized.get("confidence") or 0.5)
    normalized["validator"] = str(normalized.get("validator") or "")
    normalized["field_hints"] = [str(item).lower() for item in (normalized.get("field_hints") or [])]
    normalized["keywords"] = [str(item).lower() for item in (normalized.get("keywords") or [])]
    return normalized
