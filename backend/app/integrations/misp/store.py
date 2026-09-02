from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.config import settings


class MISPStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else settings.storage_dir / "misp" / "iocs.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        return data if isinstance(data, list) else data.get("iocs", [])

    def save(self, iocs: list[dict[str, Any]]) -> Path:
        self.path.write_text(json.dumps(iocs, ensure_ascii=False, indent=2), encoding="utf-8")
        return self.path

    def append(self, iocs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for item in self.load():
            merged[str(item.get("value", ""))] = item
        for item in iocs:
            merged[str(item.get("value", ""))] = item
        records = list(merged.values())
        self.save(records)
        return records

    def import_file(self, path: str | Path) -> list[dict[str, Any]]:
        from app.integrations.offline import load_any

        value = load_any(Path(path))
        records = value if isinstance(value, list) else value.get("iocs", value.get("items", [value]))
        return self.append([item for item in records if isinstance(item, dict)])
