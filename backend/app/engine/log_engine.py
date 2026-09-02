from pathlib import Path

from app.core.config import settings
from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.rules.sigma import evaluate_sigma, load_sigma_rules


class SigmaLogEngine(DetectionEngine):
    name = "sigma_log_engine"
    version = "1.0.0"

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        rule_dir = Path(__file__).resolve().parents[1] / "rules" / "logs"
        custom_dir = settings.integration_dir / "sigma_rules"
        findings = []
        rules = load_sigma_rules(rule_dir)
        if custom_dir.exists():
            rules.extend(load_sigma_rules(custom_dir))
        for rule in rules:
            if evaluate_sigma(rule, context.log_lines):
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    evidence={"title": rule.title, "condition": rule.condition, "detection": rule.detection},
                    recommendation=rule.recommendation,
                ).normalize())
        return findings
