"""Unified engine interfaces."""

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult, PipelineResult

__all__ = ["DetectionEngine", "DetectionContext", "DetectionResult", "PipelineResult"]

