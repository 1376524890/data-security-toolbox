from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class OfflineImportResult:
    imported: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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


def _normalize_records(value: Any, category: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        if "items" in value and isinstance(value["items"], list):
            return [item for item in value["items"] if isinstance(item, dict)]
        return [value]
    return []


def import_offline_bundle(path: Path, categories: list[str] | None = None) -> OfflineImportResult:
    result = OfflineImportResult()
    path = Path(path)
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in {".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".csv", ".tsv", ".rules"})
    else:
        result.errors.append(f"path not found: {path}")
        return result
    for file in files:
        category = file.parent.name if file.parent != path else file.stem
        if categories and category not in categories and file.stem not in categories:
            continue
        try:
            records = _normalize_records(load_any(file), category)
            result.imported += len(records)
            result.categories[category] = result.categories.get(category, 0) + len(records)
        except Exception as exc:
            result.errors.append(f"{file}: {exc}")
    return result


def export_offline_bundle(path: Path, data: dict[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path
