import logging
from typing import Iterable

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult

logger = logging.getLogger(__name__)


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
        from app.rules.library import rule_enabled, rule_snapshot

        for engine in engines:
            # One engine must not be able to take the whole target down with it.
            # A third-party binary (Suricata on a capture it cannot read) raised
            # out of here, which aborted the run, left the segment ``pending``
            # forever and held a pcap worker for the length of that binary's
            # timeout - so a slow engine throttled the capture it was supposed
            # to analyse. Every other engine's findings are still valid, so the
            # failure is recorded on the context (and surfaced as an analysis
            # result) and the run continues.
            try:
                produced = list(engine.analyze(context))
            except Exception as exc:  # noqa: BLE001 - isolate one engine's failure
                logger.warning(
                    "engine %s failed on %s %s: %s",
                    engine.name,
                    context.target_type,
                    context.target_id,
                    exc,
                )
                errors = context.data.setdefault("engine_errors", [])
                errors.append({"engine": engine.name, "error": f"{type(exc).__name__}: {exc}"})
                continue
            for finding in produced:
                key = 'CVE_LOOKUP' if finding.rule_id.startswith('CVE_') else finding.rule_id
                if engine.name != 'sigma_log_engine' and not rule_enabled(engine.name, key):
                    continue
                if 'rule_snapshot' not in finding.evidence and engine.name != 'sigma_log_engine':
                    snapshot = rule_snapshot(engine.name, finding.rule_id)
                    if snapshot:
                        finding.evidence['rule_snapshot'] = snapshot
                findings.append(finding)
        return findings
