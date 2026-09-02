from __future__ import annotations

from typing import Any

from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.engine.risk_engine.engine import RiskEngine
from app.integrations.base import AdapterResult, IntegrationAdapter


def run_adapter(
    adapter: IntegrationAdapter,
    payload: Any,
    context: DetectionContext | None = None,
    risk_engine: RiskEngine | None = None,
) -> AdapterResult:
    if context is None:
        context = DetectionContext(target_type="integration", target_id=adapter.name, data={})
    result = adapter.adapt(payload, context)
    if risk_engine:
        result.findings = risk_engine.score(context, result.findings)
    return result


def run_adapter_findings(
    adapter: IntegrationAdapter,
    payload: Any,
    context: DetectionContext | None = None,
    risk_engine: RiskEngine | None = None,
) -> list[DetectionResult]:
    return run_adapter(adapter, payload, context, risk_engine).findings
