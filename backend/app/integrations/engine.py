from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.integrations.base import IntegrationAdapter


class IntegrationAdapterEngine(DetectionEngine):
    """Bridge an IntegrationAdapter into the existing DetectionEngine pipeline."""

    def __init__(self, adapter: IntegrationAdapter, payload_key: str = "adapter_payload") -> None:
        self.adapter = adapter
        self.payload_key = payload_key
        self.name = adapter.name
        self.version = adapter.version

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        if not self.adapter.supports(context):
            return []
        payload = context.data.get(self.payload_key, {})
        if context.target_type == "pcap" and context.path and context.path.exists():
            payload = {
                "pcap": str(context.path),
                "path": str(context.path),
                "output_dir": str(settings.integration_dir / self.adapter.name),
            }
        elif not payload and context.path:
            payload = {"path": str(context.path), "context": context.to_dict()}
        elif not payload:
            payload = {"context": context.to_dict()}
        adapter_result = self.adapter.adapt(payload, context)
        context.data.setdefault("adapter_records", {})[self.adapter.name] = adapter_result.records
        return adapter_result.findings

    def metadata(self) -> dict[str, Any]:
        return {**self.adapter.metadata(), "bridge": "IntegrationAdapterEngine"}
