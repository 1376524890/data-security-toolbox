from __future__ import annotations

from pathlib import Path
from typing import Any

from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter, finding
from app.integrations.presidio.recognizers import fallback_scan, presidio_scan

ENTITY_RULES = {
    "CN_ID_CARD": ("DATA_PRESIDIO_ID_CARD_001", "High", 0.9, "身份证号属于个人敏感信息，应加密、脱敏并限制访问。"),
    "CN_PHONE": ("DATA_PRESIDIO_PHONE_001", "High", 0.9, "手机号属于个人敏感信息，应最小化采集并实施脱敏。"),
    "BANK_CARD": ("DATA_PRESIDIO_BANK_CARD_001", "High", 0.9, "银行卡号属于支付敏感信息，应加密存储并纳入支付安全审计。"),
    "MEDICAL_RECORD": ("DATA_PRESIDIO_MEDICAL_001", "High", 0.85, "病历、诊断等医疗数据属于高敏感健康数据，应实施加密和权限控制。"),
    "MEDICAL": ("DATA_PRESIDIO_MEDICAL_001", "High", 0.85, "病历、诊断等医疗数据属于高敏感健康数据，应实施加密和权限控制。"),
    "SECRET": ("DATA_PRESIDIO_SECRET_001", "Critical", 0.9, "发现明文 Secret/Token/Password，应立即轮换并清理存储。"),
}


def extract_text(payload: Any, context: DetectionContext | None = None) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        if payload.get("text"):
            return str(payload["text"])
        if payload.get("path") or payload.get("file"):
            path = Path(payload.get("path") or payload.get("file"))
            if path.exists() and path.is_file() and path.stat().st_size < 10_000_000:
                return path.read_text(encoding="utf-8", errors="replace")
    if context:
        if context.data.get("text"):
            return str(context.data["text"])
        if context.path and context.path.exists() and context.path.is_file() and context.path.stat().st_size < 10_000_000:
            return context.path.read_text(encoding="utf-8", errors="replace")
    return ""


class PresidioAdapter(IntegrationAdapter):
    name = "presidio"
    version = "2.1.0"
    supported_types = ("text", "file")

    def parse(self, payload: Any) -> list[dict[str, str]]:
        text = extract_text(payload)
        return presidio_scan(text) if text else []

    def adapt(self, payload: Any, context: DetectionContext | None = None) -> AdapterResult:
        text = extract_text(payload, context)
        records = self.parse(payload if not isinstance(payload, dict) or payload.get("text") else {"text": text})
        if not records:
            records = fallback_scan(text)
        findings: list[Any] = []
        grouped: dict[str, list[dict[str, str]]] = {}
        for record in records:
            entity = str(record.get("entity_type", ""))
            grouped.setdefault(entity, []).append(record)
        for entity, items in grouped.items():
            rule = ENTITY_RULES.get(entity)
            if not rule:
                continue
            rule_id, severity, confidence, recommendation = rule
            findings.append(finding(
                self.name,
                rule_id,
                severity,
                confidence,
                {
                    "entity_type": entity,
                    "count": len(items),
                    "samples": [item.get("text", "") for item in items[:10]],
                    "source": "presidio" if records and records != fallback_scan(text) else "regex-fallback",
                },
                recommendation,
            ))
        return AdapterResult(self.name, records, findings, {"entity_counts": {key: len(value) for key, value in grouped.items()}})
