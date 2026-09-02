from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class DetectionContext:
    target_type: str
    target_id: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None
    raw: bytes = b""
    assets: list[dict[str, Any]] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)
    packets: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    log_lines: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "target_id": self.target_id,
            "path": str(self.path) if self.path else None,
            "data": self.data,
            "assets": self.assets,
            "flows": self.flows,
            "packets": self.packets,
            "metadata": self.metadata,
            "log_lines": self.log_lines,
            "files": [str(item) for item in self.files],
            "created_at": self.created_at,
        }

