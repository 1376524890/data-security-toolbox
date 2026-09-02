from __future__ import annotations

import json
import csv
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml(path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for YAML offline bundles") from exc
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def load_rules(path: Path) -> list[dict[str, Any]]:
    from app.integrations.suricata.parser import parse_rule_file

    return parse_rule_file(path)


def load_any(path: Path) -> Any:
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl", ".ndjson"}:
        if suffix in {".jsonl", ".ndjson"}:
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return load_json(path)
    if suffix in {".yaml", ".yml"}:
        return load_yaml(path)
    if suffix in {".csv", ".tsv"}:
        return load_csv(path)
    if suffix in {".rules"}:
        return load_rules(path)
    raise ValueError(f"unsupported offline file type: {suffix}")


def export_offline_bundle(path: Path, data: dict[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
