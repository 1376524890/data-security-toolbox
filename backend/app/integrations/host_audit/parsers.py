from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_osquery_json(text: str) -> list[dict[str, Any]]:
    payload = json.loads(text)
    data = payload if isinstance(payload, list) else payload.get("data") or payload.get("rows") or []
    return [item for item in data if isinstance(item, dict)]


def parse_wazuh_events(text: str) -> list[dict[str, Any]]:
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def parse_payload(payload: Any, kind: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if payload.get("records"):
            return payload["records"]
        if payload.get("path") or payload.get("file"):
            path = Path(payload.get("path") or payload.get("file"))
            if path.exists():
                return parse_osquery_json(path.read_text(encoding="utf-8", errors="replace")) if kind == "osquery" else parse_wazuh_events(path.read_text(encoding="utf-8", errors="replace"))
        format_name = str(payload.get("format") or payload.get("kind") or "").lower()
        if payload.get("json") and format_name in {"", "osquery", "wazuh", kind}:
            text = str(payload["json"])
        elif payload.get("text") and format_name in {"osquery", "wazuh", kind}:
            text = str(payload["text"])
        else:
            return []
        return parse_osquery_json(text) if kind == "osquery" else parse_wazuh_events(text)
    if isinstance(payload, (str, Path)):
        path = Path(payload)
        if path.exists():
            return parse_osquery_json(path.read_text(encoding="utf-8", errors="replace")) if kind == "osquery" else parse_wazuh_events(path.read_text(encoding="utf-8", errors="replace"))
    return []
