from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.engine.core.result import DetectionResult


@dataclass
class AdapterResult:
    adapter: str
    records: list[dict[str, Any]] = field(default_factory=list)
    findings: list[DetectionResult] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "record_count": len(self.records),
            "finding_count": len(self.findings),
            "summary": self.summary,
            "findings": [item.to_dict() for item in self.findings],
        }


class IntegrationAdapter(ABC):
    name: str = "base"
    version: str = "1.0.0"
    supported_types: tuple[str, ...] = ()

    @abstractmethod
    def adapt(self, payload: Any, context: Any | None = None) -> AdapterResult:
        """Convert third-party input into unified DetectionResult findings."""

    def parse(self, payload: Any) -> list[dict[str, Any]]:
        """Parse raw third-party output into normalized records."""
        return []

    def metadata(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version, "supported_types": list(self.supported_types)}


def finding(
    adapter: str,
    rule_id: str,
    severity: str,
    confidence: float,
    evidence: dict[str, Any],
    recommendation: str,
    timestamp: str = "",
) -> DetectionResult:
    from app.engine.core.result import DetectionResult

    return DetectionResult(
        engine=adapter,
        rule_id=rule_id,
        severity=severity,
        confidence=float(confidence),
        evidence=evidence,
        recommendation=recommendation,
        timestamp=timestamp or datetime.now(UTC).isoformat(),
    ).normalize()


def severity_map(value: Any, default: str = "Medium") -> str:
    normalized = str(value or "").strip().lower()
    mapping = {
        "1": "Critical",
        "2": "High",
        "3": "Medium",
        "4": "Low",
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "error": "High",
        "fail": "High",
        "failed": "High",
        "warn": "Medium",
        "info": "Low",
    }
    return mapping.get(normalized, default)
