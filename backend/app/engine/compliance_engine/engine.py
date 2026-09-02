from pathlib import Path

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.rules.interpreter import interpret_rules


class ComplianceEngine(DetectionEngine):
    name = "compliance_engine"
    version = "2.0.0"

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        db_types = {"redis", "mysql", "postgresql", "mongodb", "oracle", "database"}
        public_databases = [asset for asset in context.assets if asset.get("asset_type") in db_types and asset.get("public_exposed", context.data.get("public_exposed", False))]
        weak_protocols = [asset for asset in context.assets if asset.get("service", "").lower() in {"telnet", "ftp", "smtp"}]
        context.data["public_database_count"] = len(public_databases)
        context.data["weak_protocol_count"] = len(weak_protocols)
        rule_dir = Path(__file__).resolve().parents[2] / "rules" / "compliance"
        findings = interpret_rules(context, rule_dir)
        if weak_protocols:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="COMP_WEAK_PROTOCOL_001",
                severity="High",
                confidence=0.9,
                evidence={"services": weak_protocols[:50]},
                recommendation="禁用明文/弱认证协议，改用 SSH、SFTP、TLS 等加密协议。",
            ).normalize())
        return findings
