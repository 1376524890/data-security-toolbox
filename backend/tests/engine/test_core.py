from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.core.result import DetectionResult
from app.engine.risk_engine.engine import RiskEngine


def test_registry_and_pipeline() -> None:
    pipeline = DetectionPipeline(registry, RiskEngine())
    result = pipeline.run(DetectionContext(target_type="manual", data={}))
    assert result.target_type == "manual"
    assert isinstance(result.risk_level, str)


def test_result_normalization() -> None:
    item = DetectionResult(engine="test", rule_id="T", severity="critical", confidence=2.0).normalize()
    assert item.severity == "Critical"
    assert item.confidence == 1.0

