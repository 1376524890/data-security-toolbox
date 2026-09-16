"""Detection context.

Deliberately distinct from the platform pipeline context
(``app.engine.core.context.DetectionContext``); an adapter bridges the two so the
existing pipeline class keeps its contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Who is asking. Kept small and closed so reports stay comparable.
SOURCE_TYPES = ("file", "text", "network", "database", "metadata")


@dataclass(slots=True)
class SensitiveDetectionContext:
    """One unit of text to classify, plus the evidence around it.

    ``text`` is used in memory only and must never be serialised into a report,
    a log line or an evidence record.
    """

    text: str = ""
    field_name: str = ""
    file_name: str = ""
    path: str = ""
    sheet_name: str = ""
    content_type: str = ""
    source_type: str = "text"
    protocol: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_text(self, text: str) -> "SensitiveDetectionContext":
        return SensitiveDetectionContext(
            text=text,
            field_name=self.field_name,
            file_name=self.file_name,
            path=self.path,
            sheet_name=self.sheet_name,
            content_type=self.content_type,
            source_type=self.source_type,
            protocol=self.protocol,
            metadata=dict(self.metadata),
        )
