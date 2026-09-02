from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter, finding, severity_map
from app.integrations.host_audit.parsers import parse_payload
from app.core.config import settings


class WazuhAdapter(IntegrationAdapter):
    name = "wazuh"
    version = "2.1.0"
    supported_types = ("alert", "asset", "process", "user", "config", "log")
    capabilities = ("alert", "asset", "process", "user", "config", "log")

    def health(self) -> dict[str, Any]:
        configured = bool(settings.wazuh_url)
        return {
            "name": self.name,
            "adapter_version": self.version,
            "installed": True,
            "enabled": True,
            "healthy": configured,
            "runtime_version": settings.wazuh_url or "offline-parser",
            "supported_types": list(self.supported_types),
            "capabilities": list(self.capabilities),
            "last_check": datetime.now(UTC).isoformat(),
            "status": "ready" if configured else "unavailable",
            "message": "" if configured else "Wazuh API not configured; offline parser available",
        }

    def parse(self, payload: Any) -> list[dict[str, Any]]:
        return parse_payload(payload, "wazuh")

    def adapt(self, payload: Any, context: DetectionContext | None = None) -> AdapterResult:
        records = self.parse(payload)
        findings: list[Any] = []
        for record in records:
            rule = record.get("rule") or {}
            level = int(rule.get("level") or record.get("level") or 0)
            description = str(rule.get("description") or record.get("description") or "")
            if level >= 12:
                findings.append(finding(
                    self.name,
                    f"WAZUH_{rule.get('id', 'ALERT')}",
                    severity_map("Critical"),
                    0.9,
                    {"record": record, "rule_id": rule.get("id"), "level": level, "description": description},
                    "Wazuh 高等级告警应进入事件调查。",
                    str(record.get("timestamp", "")),
                ))
            elif level >= 6:
                findings.append(finding(
                    self.name,
                    f"WAZUH_{rule.get('id', 'ALERT')}",
                    severity_map("Medium"),
                    0.8,
                    {"record": record, "rule_id": rule.get("id"), "level": level, "description": description},
                    "结合 Wazuh 规则检查主机行为。",
                    str(record.get("timestamp", "")),
                ))
        return AdapterResult(self.name, records, findings, {"records": len(records), "findings": len(findings)})
