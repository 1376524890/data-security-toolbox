import hashlib

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.rules.sigma import load_sigma_rules, matching_lines
from app.rules.library import rule_files


class SigmaLogEngine(DetectionEngine):
    name = "sigma_log_engine"
    version = "1.0.0"

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        findings = []
        if not context.log_lines:
            return findings
        rules = [rule for path in rule_files(self.name) for rule in load_sigma_rules(path)]
        for rule in rules:
            matched = matching_lines(rule, context.log_lines, context.data.get('logsource'))
            if matched:
                findings.append(DetectionResult(
                    engine=self.name,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    evidence={"title": rule.title, "condition": rule.condition,
                              "detection": rule.detection, "matches": matched[:20],
                              "match_count": len(matched),
                              "rule_snapshot": {
                                  "rule_id": rule.rule_id, "engine": self.name, "type": "sigma",
                                  "title": rule.title, "condition": rule.condition,
                                  "severity": rule.severity, "recommendation": rule.recommendation,
                                  "file": rule.path, "path": rule.path, "content": rule.content,
                                  "detection": rule.detection,
                                  "sha256": hashlib.sha256(rule.content.encode()).hexdigest(),
                              }},
                    recommendation=rule.recommendation,
                ).normalize())
        return findings
