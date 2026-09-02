from typing import Any

from app.engine.core.context import DetectionContext
from app.engine.core.registry import EngineRegistry
from app.engine.core.result import DetectionResult, PipelineResult


class DetectionPipeline:
    def __init__(self, registry: EngineRegistry, risk_engine: Any) -> None:
        self.registry = registry
        self.risk_engine = risk_engine

    def run(self, context: DetectionContext) -> PipelineResult:
        findings: list[DetectionResult] = self.registry.run(context)
        if self.risk_engine:
            findings = self.risk_engine.score(context, findings)
        score = max((item.risk_score for item in findings), default=0.0)
        level = self.risk_engine.level(score)
        summary = {
            "engine_count": len(self.registry.all()),
            "finding_count": len(findings),
            "severities": {item.severity: sum(1 for f in findings if f.severity == item.severity) for item in findings},
        }
        return PipelineResult(context.target_type, context.target_id, findings, score, level, summary)

