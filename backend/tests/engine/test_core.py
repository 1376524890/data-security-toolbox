from app.engine import registry
from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.core.registry import EngineRegistry
from app.engine.core.result import DetectionResult
from app.engine.risk_engine.engine import RiskEngine


def test_registry_and_pipeline() -> None:
    pipeline = DetectionPipeline(registry, RiskEngine())
    result = pipeline.run(DetectionContext(target_type="manual", data={}))
    assert result.target_type == "manual"
    assert isinstance(result.risk_level, str)


def test_result_normalization() -> None:
    item = DetectionResult(
        engine="test", rule_id="T", severity="critical", confidence=2.0
    ).normalize()
    assert item.severity == "Critical"
    assert item.confidence == 1.0


class _Boom(DetectionEngine):
    name = "boom_engine"

    def analyze(self, context):
        raise RuntimeError("Suricata analysis failed: pcap_next_ex(): -2")


class _Fine(DetectionEngine):
    name = "fine_engine"

    def analyze(self, context):
        return [
            DetectionResult(engine=self.name, rule_id="OK_1", severity="Low", confidence=1.0)
        ]


def test_one_failing_engine_does_not_abort_the_run() -> None:
    """A raising engine must not take the whole target's findings with it.

    Regression: Suricata raising out of the registry aborted the run, so the
    segment stayed ``pending`` forever and the pcap worker was held for the
    length of Suricata's timeout. The failure must be recorded, not fatal.
    """
    registry = EngineRegistry()
    registry.register(_Boom())
    registry.register(_Fine())
    context = DetectionContext(target_type="pcap", target_id="1", data={})
    findings = registry.run(context)
    assert [item.rule_id for item in findings] == ["OK_1"]
    assert context.data["engine_errors"] == [
        {
            "engine": "boom_engine",
            "error": "RuntimeError: Suricata analysis failed: pcap_next_ex(): -2",
        }
    ]
