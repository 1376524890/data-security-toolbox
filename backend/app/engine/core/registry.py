from typing import Iterable

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult


class EngineRegistry:
    def __init__(self) -> None:
        self._engines: dict[str, DetectionEngine] = {}

    def register(self, engine: DetectionEngine) -> None:
        self._engines[engine.name] = engine

    def get(self, name: str) -> DetectionEngine:
        if name not in self._engines:
            raise KeyError(f"unknown engine: {name}")
        return self._engines[name]

    def all(self) -> list[DetectionEngine]:
        return list(self._engines.values())

    def run(self, context: DetectionContext, names: Iterable[str] | None = None) -> list[DetectionResult]:
        engines = self.all() if names is None else [self.get(name) for name in names]
        findings: list[DetectionResult] = []
        for engine in engines:
            findings.extend(engine.analyze(context))
        return findings

