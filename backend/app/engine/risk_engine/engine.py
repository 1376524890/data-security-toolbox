from typing import Any

from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult


class RiskEngine:
    name = "risk_engine"
    version = "1.0.0"

    WEIGHTS = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    def weight(self, severity: str) -> float:
        return float(self.WEIGHTS.get(severity.title(), 1))

    def exposure_factor(self, context: DetectionContext) -> float:
        value = context.data.get("exposure_factor", context.data.get("public_exposed", False))
        if isinstance(value, bool):
            return 4.0 if value else 2.0
        return float(value)

    def data_sensitivity(self, context: DetectionContext) -> float:
        return float(context.data.get("data_sensitivity", 1))

    def threat_factor(self, context: DetectionContext) -> float:
        return float(context.data.get("threat_factor", 1))

    def score(self, context: DetectionContext, findings: list[DetectionResult]) -> list[DetectionResult]:
        exposure = self.exposure_factor(context)
        sensitivity = self.data_sensitivity(context)
        threat = self.threat_factor(context)
        for finding in findings:
            base = self.weight(finding.severity) * 20.0
            factor = (exposure / 2.0) * sensitivity * threat * float(finding.confidence)
            finding.risk_score = round(min(100.0, base * factor), 2)
            finding.risk_level = self.level(finding.risk_score)
            finding.evidence["risk_model"] = {
                "asset_weight": self.weight(finding.severity),
                "exposure_factor": exposure,
                "data_sensitivity": sensitivity,
                "threat_factor": threat,
                "confidence": finding.confidence,
            }
        return findings

    def level(self, score: float) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"
