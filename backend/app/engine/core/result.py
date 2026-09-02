from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class DetectionResult:
    engine: str
    rule_id: str
    severity: str
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    risk_score: float = 0.0
    risk_level: str = "Low"

    def normalize(self) -> "DetectionResult":
        self.severity = self.severity.title()
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PipelineResult:
    target_type: str
    target_id: str | None
    findings: list[DetectionResult] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "Low"
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "target_id": self.target_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "findings": [item.to_dict() for item in self.findings],
        }

