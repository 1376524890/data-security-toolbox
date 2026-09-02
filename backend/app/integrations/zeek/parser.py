from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ZEEK_EVENT_TYPES = {"conn", "dns", "http", "ssl", "files", "weird"}


def _event_type(record: dict[str, Any], fallback: str) -> str:
    value = record.get("_path") or record.get("event_type") or record.get("event") or fallback
    return str(value).lower()


def parse_json_lines(text: str, source: str = "zeek") -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    fallback = Path(source).stem if source.endswith((".log", ".json", ".jsonl", ".ndjson")) else "zeek"
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            item = dict(item)
            item.setdefault("event_type", _event_type(item, fallback))
            records.append(item)
    return records


def parse_json_file(path: Path) -> list[dict[str, Any]]:
    return parse_json_lines(path.read_text(encoding="utf-8", errors="replace"), str(path))


def parse_tsv_log(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8", errors="replace") as handle:
        lines = handle.readlines()
    header_index = 0
    for idx, line in enumerate(lines):
        if line.startswith("#fields"):
            header_index = idx
            break
    if not lines or header_index >= len(lines):
        return []
    header = lines[header_index].strip().lstrip("#fields").split("\t")
    for line in lines[header_index + 1 :]:
        if not line.strip() or line.startswith("#"):
            continue
        values = line.rstrip("\n").split("\t")
        record = dict(zip(header, values))
        record["event_type"] = path.stem.lower()
        records.append(record)
    return records


def parse_zeek_dir(directory: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    directory = Path(directory)
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        if path.suffix in {".json", ".jsonl", ".ndjson"}:
            records.extend(parse_json_file(path))
        elif path.suffix == ".log":
            records.extend(parse_tsv_log(path))
    return records


def parse_zeek_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if payload.get("records"):
            return payload["records"]
        log_dir = payload.get("log_dir") or payload.get("directory")
        if log_dir:
            return parse_zeek_dir(Path(log_dir))
        if payload.get("pcap") or payload.get("path"):
            return []
        if payload.get("json"):
            return parse_json_lines(str(payload["json"]), "zeek")
    if isinstance(payload, (str, Path)):
        path = Path(payload)
        if path.is_dir():
            return parse_zeek_dir(path)
        if path.suffix in {".json", ".jsonl", ".ndjson"}:
            return parse_json_file(path)
        if path.suffix == ".log":
            return parse_tsv_log(path)
    return []
