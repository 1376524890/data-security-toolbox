from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SUPPORTED_EVENT_TYPES = {"alert", "flow", "dns", "http", "fileinfo"}


def parse_eve_lines(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            item = dict(item)
            item["event_type"] = str(item.get("event_type", "unknown")).lower()
            records.append(item)
    return records


def parse_eve_file(path: Path) -> list[dict[str, Any]]:
    return parse_eve_lines(path.read_text(encoding="utf-8", errors="replace"))


def parse_eve_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if payload.get("records"):
            return payload["records"]
        if payload.get("path") or payload.get("eve_file"):
            return parse_eve_file(Path(payload.get("path") or payload.get("eve_file")))
        if payload.get("json"):
            return parse_eve_lines(str(payload["json"]))
        if payload.get("text"):
            return parse_eve_lines(str(payload["text"]))
    if isinstance(payload, (str, Path)):
        path = Path(payload)
        return parse_eve_file(path) if path.is_file() else []
    return []


def event_records(records: list[dict[str, Any]], event_type: str | None = None) -> list[dict[str, Any]]:
    if event_type is None:
        return [item for item in records if item.get("event_type", "").lower() in SUPPORTED_EVENT_TYPES]
    return [item for item in records if item.get("event_type", "").lower() == event_type.lower()]


RULES_RE = re.compile(r"^\s*alert\s+(\S+)\s+(\S+)\s+(\S+)\s+.*?\(([^)]*)\)", re.IGNORECASE)


def parse_rule_file(path: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = RULES_RE.match(line)
        if not match:
            continue
        options_text = match.group(4)
        options: dict[str, Any] = {}
        for key, value in re.findall(r"([A-Za-z0-9_]+)\s*:\s*([^;]+)", options_text):
            options[key] = value.strip().strip('"')
        rules.append({
            "raw": line,
            "action": match.group(1),
            "protocol": match.group(2),
            "source": match.group(3),
            "destination": match.group(4),
            "msg": options.get("msg", ""),
            "sid": options.get("sid", ""),
            "rev": options.get("rev", ""),
            "classtype": options.get("classtype", ""),
            "reference": options.get("reference", ""),
        })
    return rules


def parse_rule_dir(directory: Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted(Path(directory).rglob("*.rules")):
        rules.extend(parse_rule_file(path))
    return rules
