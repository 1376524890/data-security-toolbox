from abc import ABC, abstractmethod
from typing import Any

from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult


class DetectionEngine(ABC):
    name: str = "base"
    version: str = "1.0.0"

    @abstractmethod
    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        """Analyze a context and return unified detection results."""

    def metadata(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version}

