from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.config import settings
from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter, finding, severity_map
from app.integrations.host_audit.parsers import parse_payload
from app.integrations.host_audit.wazuh_client import WazuhClient


class WazuhAdapter(IntegrationAdapter):
    name = "wazuh"
    version = "2.2.0"
    supported_types = ("alert", "asset", "process", "user", "config", "log")
    capabilities = ("alert", "asset", "process", "user", "config", "log", "api-sync")

    @property
    def configured(self) -> bool:
        return bool(settings.wazuh_url and settings.wazuh_user and settings.wazuh_password)

    def supports(self, context: DetectionContext | None = None) -> bool:
        return bool(context and context.target_type in {"host", "audit", "asset", "log"} or (context and context.data.get("wazuh")))

    def health(self) -> dict[str, Any]:
        configured = self.configured
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

    def fetch(self, limit: int = 0, start: str = "") -> list[dict[str, Any]]:
        """Pull the most recent alerts from the configured Wazuh API."""
        if not self.configured:
            return []
        client = WazuhClient(settings.wazuh_url, settings.wazuh_user, settings.wazuh_password, bool(settings.wazuh_verify_tls))
        return client.fetch_alerts(limit or settings.wazuh_alert_limit, start)

    def adapt(self, payload: Any, context: DetectionContext | None = None) -> AdapterResult:
        if isinstance(payload, dict) and payload.get("sync"):
            limit = int(payload.get("limit") or settings.wazuh_alert_limit)
            start = str(payload.get("start") or "")
            records = self.fetch(limit, start)
        else:
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