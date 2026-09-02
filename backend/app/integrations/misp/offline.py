from __future__ import annotations

from pathlib import Path
from typing import Any

from app.integrations.misp.store import MISPStore


def import_offline_iocs(path: str | Path, store: MISPStore | None = None) -> list[dict[str, Any]]:
    store = store or MISPStore()
    return store.import_file(path)


def export_offline_iocs(path: str | Path, iocs: list[dict[str, Any]]) -> Path:
    store = MISPStore(path)
    return store.save(iocs)
