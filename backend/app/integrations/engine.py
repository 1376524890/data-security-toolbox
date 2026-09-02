from __future__ import annotations

from typing import Any

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
        payload = context.data.get(self.payload_key, {})
        if payload is None and context.path:
            payload = {"path": str(context.path), "context": context.to_dict()}
        return self.adapter.adapt(payload, context).findings

    def metadata(self) -> dict[str, Any]:
        return {**self.adapter.metadata(), "bridge": "IntegrationAdapterEngine"}
