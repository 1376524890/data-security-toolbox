from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.risk_engine.engine import RiskEngine
from app.integrations import integration_registry
from app.integrations.runner import run_adapter


def test_integration_registry_has_adapters() -> None:
    names = {item.name for item in integration_registry.all()}
    assert {"zeek", "suricata", "presidio", "misp", "osquery", "wazuh", "openscap"} <= names


def test_run_adapter_scores_findings() -> None:
    context = DetectionContext(target_type="integration", data={"exposure_factor": 4})
    result = run_adapter(integration_registry.get("presidio"), {"text": "api_key=sk-1234567890abcdef"}, context, RiskEngine())
    assert result.findings
    assert result.findings[0].risk_score > 0


def test_adapter_engine_runs_in_pipeline() -> None:
    from app.engine import registry

    context = DetectionContext(target_type="text", target_id="sample", data={"adapter_payload": {"text": "身份证 110101199003071234"}})
    pipeline_result = DetectionPipeline(registry, RiskEngine()).run(context)
    engines = {item.engine for item in pipeline_result.findings}
    assert "presidio" in engines
