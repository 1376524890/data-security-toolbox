from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter, finding, severity_map
from app.integrations.openscap.parser import parse_openscap_payload


class OpenSCAPAdapter(IntegrationAdapter):
    name = "openscap"
    version = "2.1.0"
    supported_types = ("cis", "dengbao", "xccdf", "arf")
    capabilities = ("xccdf", "arf", "cis", "dengbao")

    def supports(self, context: DetectionContext | None = None) -> bool:
        return bool(context and context.target_type in {"host", "compliance"} or (context and context.data.get("openscap")))

    def health(self) -> dict[str, Any]:
        runtime = self._binary_available("oscap")
        return {
            "name": self.name,
            "adapter_version": self.version,
            "installed": bool(runtime),
            "enabled": True,
            "healthy": bool(runtime),
            "runtime_version": runtime,
            "supported_types": list(self.supported_types),
            "capabilities": list(self.capabilities),
            "last_check": datetime.now(UTC).isoformat(),
            "status": "ready" if runtime else "unavailable",
            "message": "" if runtime else "OpenSCAP scanner not found",
        }

    def parse(self, payload: Any) -> list[dict[str, Any]]:
        return parse_openscap_payload(payload)

    def adapt(self, payload: Any, context: DetectionContext | None = None) -> AdapterResult:
        records = self.parse(payload)
        findings: list[Any] = []
        for record in records:
            result = str(record.get("result", "")).lower()
            if result in {"pass", "notchecked", "notapplicable", "unknown", ""}:
                continue
            rule_id = str(record.get("idref") or record.get("rule_id") or "")
            title = str(record.get("title") or "")
            benchmark = str(record.get("benchmark") or "")
            profile = str(record.get("profile") or "")
            severity = "High" if result in {"fail", "error", "failed"} else "Medium"
            evidence = {"record": record, "result": result, "profile": profile, "benchmark": benchmark, "cve": record.get("cve", "")}
            findings.append(finding(
                self.name,
                f"OPENSCAP_{rule_id or 'RESULT'}",
                severity_map(severity),
                0.85,
                evidence,
                f"根据 {profile or 'CIS/等保'} 基线修复 {title or rule_id}。",
            ))
        return AdapterResult(self.name, records, findings, {"failed": sum(1 for r in records if str(r.get("result", "")).lower() in {"fail", "error", "failed"})})
