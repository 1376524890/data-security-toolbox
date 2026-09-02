from __future__ import annotations

import json
import re
import shutil
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import IOC, LocalCve, OfflineResource


IOC_TYPE_ALIASES = {
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "ip-dst": "ip",
    "ip-src": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "hash": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "sha512": "hash",
}


@dataclass
class OfflineImportResult:
    imported: int = 0
    duplicates: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    resources: list[dict[str, Any]] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def safe_resolve(base: Path, candidate: str | Path) -> Path:
    root = Path(base).resolve()
    target = Path(candidate)
    if not target.is_absolute():
        target = root / target
    target = target.resolve()
    if not target.is_relative_to(root):
        raise ValueError("path escapes managed offline directory")
    return target


def _normalize_ioc_type(value: Any) -> str:
    return IOC_TYPE_ALIASES.get(str(value or "").lower().strip(), "unknown")


def _records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in ("items", "iocs", "resources", "vulnerabilities", "results", "rules"):
            if key in value and isinstance(value[key], list):
                return [item for item in value[key] if isinstance(item, dict)]
        return [value]
    return []


def _load_document(path: Path) -> Any:
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl", ".ndjson"}:
        if suffix in {".jsonl", ".ndjson"}:
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return json.loads(path.read_text(encoding="utf-8"))
    if suffix in {".yaml", ".yml"}:
        import yaml

        return yaml.safe_load(path.read_text(encoding="utf-8"))
    if suffix in {".csv", ".tsv"}:
        import csv

        with path.open(newline="", encoding="utf-8") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    if suffix == ".rules":
        from app.integrations.suricata.parser import parse_rule_file

        return parse_rule_file(path)
    raise ValueError(f"unsupported resource file: {path.suffix}")


def _resource_name(path: Path, resource_type: str, provided: str) -> str:
    if provided:
        return provided
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", path.stem) or f"{resource_type}_{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"


def _version_from_document(document: Any, provided: str) -> str:
    if provided:
        return provided
    if isinstance(document, dict):
        return str(document.get("version") or document.get("bundle_version") or document.get("schema_version") or "1.0.0")
    return "1.0.0"


def _stage_file(filename: str, content: bytes) -> Path:
    staging = settings.storage_dir / "offline_staging"
    staging.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename).name.replace("..", "").strip() or "bundle.dat"
    target = staging / f"{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}_{safe_name}"
    target.write_bytes(content)
    return target


def _resource_dir(resource_type: str) -> Path:
    return settings.integration_dir / resource_type


def _save_imported_file(source: Path, resource_type: str, name: str, version: str) -> Path:
    target_dir = _resource_dir(resource_type)
    target_dir.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix or ".json"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name) or f"{resource_type}_{version}"
    target = target_dir / f"{safe_name}_{version}{suffix}"
    shutil.copy2(source, target)
    return target


def _upsert_iocs(db: Session, records: list[dict[str, Any]]) -> tuple[int, int]:
    imported = 0
    duplicates = 0
    for record in records:
        value = str(record.get("value") or record.get("ioc") or record.get("indicator") or "").strip()
        if not value:
            continue
        ioc_type = _normalize_ioc_type(record.get("type") or record.get("ioc_type"))
        if ioc_type == "unknown":
            ioc_type = "ip" if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", value) else "domain"
        source = str(record.get("source") or "offline")
        existing = db.scalar(select(IOC).where(IOC.value == value, IOC.ioc_type == ioc_type))
        if existing:
            existing.source = source
            existing.last_seen = str(record.get("last_seen") or existing.last_seen or "")
            existing.tags = list(record.get("tags") or existing.tags or [])
            existing.extra = {**(existing.extra or {}), **record}
            duplicates += 1
        else:
            db.add(IOC(
                ioc_type=ioc_type,
                value=value,
                source=source,
                first_seen=str(record.get("first_seen") or record.get("last_seen") or ""),
                last_seen=str(record.get("last_seen") or ""),
                tags=list(record.get("tags") or []),
                extra=record,
            ))
            imported += 1
    return imported, duplicates


def _import_cves(db: Session, records: list[dict[str, Any]]) -> tuple[int, int]:
    imported = 0
    duplicates = 0
    for record in records:
        cve_id = str(record.get("cve_id") or record.get("id") or record.get("cve", {}).get("id") or "").strip()
        if not cve_id:
            continue
        cve_obj = record.get("cve", {})
        description = record.get("description") or cve_obj.get("description") or {}
        if isinstance(description, list):
            description = " ".join(str(item.get("value", item)) for item in description if isinstance(item, dict))
        severity = str(record.get("severity") or cve_obj.get("severity") or "Medium")
        cvss_score = float(record.get("cvss_score") or record.get("cvss") or cve_obj.get("cvssScore") or cve_obj.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0) if isinstance(cve_obj.get("metrics"), dict) else 0)
        existing = db.scalar(select(LocalCve).where(LocalCve.cve_id == cve_id))
        if existing:
            existing.severity = severity
            existing.cvss_score = cvss_score
            existing.description = {"text": description} if isinstance(description, str) else description
            duplicates += 1
        else:
            db.add(LocalCve(
                cve_id=cve_id,
                source=str(record.get("source") or "offline"),
                severity=severity,
                cvss_score=cvss_score,
                published=str(record.get("published") or cve_obj.get("published") or ""),
                modified=str(record.get("modified") or cve_obj.get("lastModified") or ""),
                description={"text": description} if isinstance(description, str) else description,
            ))
            imported += 1
    return imported, duplicates


def _import_models(db: Session, records: list[dict[str, Any]]) -> tuple[int, int]:
    imported = 0
    duplicates = 0
    for record in records:
        name = str(record.get("name") or "")
        if not name:
            continue
        existing = db.scalar(select(OfflineResource).where(OfflineResource.resource_type == "model", OfflineResource.name == name, OfflineResource.version == str(record.get("version", "1.0.0"))))
        if existing:
            duplicates += 1
            continue
        model_path = safe_resolve(settings.integration_dir / "models", str(record.get("path") or "")) if record.get("path") else ""
        db.add(OfflineResource(
            resource_type="model",
            name=name,
            version=str(record.get("version", "1.0.0")),
            count=1,
            status="imported",
            storage_path=str(model_path or ""),
            resource_metadata={"language": record.get("language", ""), "enabled": bool(record.get("enabled", True)), **record},
        ))
        imported += 1
    return imported, duplicates


def _import_rules(db: Session, path: Path, name: str, version: str) -> tuple[int, int]:
    from app.integrations.suricata.parser import parse_rule_file

    rules = parse_rule_file(path)
    target = _save_imported_file(path, "suricata_rules", name, version)
    existing = db.scalar(select(OfflineResource).where(OfflineResource.resource_type == "suricata_rules", OfflineResource.name == name, OfflineResource.version == version))
    if existing:
        existing.count = len(rules)
        existing.storage_path = str(target)
        existing.status = "imported"
        existing.resource_metadata = {"rule_count": len(rules), "source": "offline"}
        return 0, len(rules)
    db.add(OfflineResource(resource_type="suricata_rules", name=name, version=version, count=len(rules), status="imported", storage_path=str(target), resource_metadata={"rule_count": len(rules), "source": "offline"}))
    return len(rules), 0


def _import_sigma(db: Session, path: Path, name: str, version: str) -> tuple[int, int]:
    document = _load_document(path)
    records = _records(document)
    if not records and isinstance(document, dict):
        records = [document]
    target = _save_imported_file(path, "sigma_rules", name, version)
    existing = db.scalar(select(OfflineResource).where(OfflineResource.resource_type == "sigma_rules", OfflineResource.name == name, OfflineResource.version == version))
    count = len(records)
    if existing:
        existing.count = count
        existing.storage_path = str(target)
        existing.status = "imported"
        existing.resource_metadata = {"rule_count": count, "source": "offline"}
        return 0, count
    db.add(OfflineResource(resource_type="sigma_rules", name=name, version=version, count=count, status="imported", storage_path=str(target), resource_metadata={"rule_count": count, "source": "offline"}))
    return count, 0


def _resource_manifest(resources: list[dict[str, Any]], version: str) -> dict[str, Any]:
    return {
        "bundle_version": version,
        "created_at": datetime.now(UTC).isoformat(),
        "resources": resources,
    }


def import_offline_path(db: Session, path: str | Path, resource_type: str | None = None, name: str | None = None, version: str | None = None) -> OfflineImportResult:
    result = OfflineImportResult()
    source = Path(path)
    if not source.exists():
        result.errors.append(f"path not found: {source}")
        return result
    if source.is_dir():
        files = sorted(
            item
            for item in source.rglob("*")
            if item.is_file() and item.suffix.lower() in {".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".csv", ".tsv", ".rules"}
        )
        if not files:
            result.errors.append(f"no supported resources in directory: {source}")
            return result
        type_aliases = {"iocs": "ioc", "cves": "cve", "rules": "suricata_rules", "sigma": "sigma_rules", "models": "model"}
        for file in files:
            inferred_type = file.parent.name if file.parent != source else file.stem
            inferred_type = type_aliases.get(inferred_type, inferred_type)
            if resource_type and inferred_type not in {resource_type, f"{resource_type}s"}:
                continue
            child = import_offline_path(db, file, inferred_type or resource_type, name, version)
            result.imported += child.imported
            result.duplicates += child.duplicates
            for key, value in child.categories.items():
                result.categories[key] = result.categories.get(key, 0) + value
            result.resources.extend(child.resources)
            result.errors.extend(child.errors)
        if result.resources:
            result.manifest = _resource_manifest(result.resources, version or "1.0.0")
        return result
    try:
        document = _load_document(source)
        resource_type = resource_type or source.parent.name or source.stem
        resource_name = _resource_name(source, resource_type, name or "")
        resource_version = _version_from_document(document, version or "")
        if resource_type in {"ioc", "iocs", "threat_intel"}:
            records = [item for item in _records(document) if item.get("value") or item.get("ioc")]
            imported, duplicates = _upsert_iocs(db, records)
            result.imported += imported
            result.duplicates += duplicates
            result.categories["ioc"] = imported
            target = _save_imported_file(source, "iocs", resource_name, resource_version)
        elif resource_type in {"suricata", "suricata_rules"}:
            imported, duplicates = _import_rules(db, source, resource_name, resource_version)
            result.imported += imported
            result.duplicates += duplicates
            result.categories["suricata_rules"] = imported
            target = _resource_dir("suricata_rules")
        elif resource_type in {"sigma", "sigma_rules"}:
            imported, duplicates = _import_sigma(db, source, resource_name, resource_version)
            result.imported += imported
            result.duplicates += duplicates
            result.categories["sigma_rules"] = imported
            target = _resource_dir("sigma_rules")
        elif resource_type in {"cve", "cves", "vulnerability", "vulnerabilities"}:
            records = _records(document)
            imported, duplicates = _import_cves(db, records)
            result.imported += imported
            result.duplicates += duplicates
            result.categories["cve"] = imported
            target = _save_imported_file(source, "cves", resource_name, resource_version)
        elif resource_type in {"model", "models", "presidio"}:
            records = _records(document)
            imported, duplicates = _import_models(db, records)
            result.imported += imported
            result.duplicates += duplicates
            result.categories["model"] = imported
            target = _save_imported_file(source, "models", resource_name, resource_version)
        else:
            records = _records(document)
            imported, duplicates = _upsert_iocs(db, records)
            result.imported += imported
            result.duplicates += duplicates
            result.categories["ioc"] = imported
            target = _save_imported_file(source, "iocs", resource_name, resource_version)
        db.flush()
        existing_resource = db.scalar(select(OfflineResource).where(OfflineResource.resource_type == resource_type, OfflineResource.name == resource_name, OfflineResource.version == resource_version))
        if existing_resource:
            existing_resource.count = result.imported + result.duplicates
            existing_resource.status = "imported"
            existing_resource.storage_path = str(target)
            existing_resource.resource_metadata = {"source": "offline", "resource_type": resource_type}
            db.flush()
        else:
            resource = OfflineResource(
                resource_type=resource_type,
                name=resource_name,
                version=resource_version,
                count=result.imported + result.duplicates,
                status="imported",
                storage_path=str(target),
                resource_metadata={"source": "offline", "resource_type": resource_type},
            )
            db.add(resource)
            db.flush()
        resource_dict = {"type": resource_type, "name": resource_name, "version": resource_version, "file": str(target)}
        result.resources.append(resource_dict)
        result.manifest = _resource_manifest(result.resources, resource_version)
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        result.errors.append(f"{source}: {exc}")
        return result


def import_uploaded_offline(db: Session, filename: str, content: bytes, resource_type: str | None = None, name: str | None = None, version: str | None = None) -> OfflineImportResult:
    staged = _stage_file(filename, content)
    try:
        return import_offline_path(db, staged, resource_type, name, version)
    finally:
        staged.unlink(missing_ok=True)


def list_offline_resources(db: Session) -> list[dict[str, Any]]:
    rows = db.scalars(select(OfflineResource).order_by(OfflineResource.imported_at.desc())).all()
    return [
        {
            "id": item.id,
            "resource_type": item.resource_type,
            "name": item.name,
            "version": item.version,
            "count": item.count,
            "status": item.status,
            "storage_path": item.storage_path,
            "manifest_path": item.manifest_path,
            "resource_metadata": item.resource_metadata,
            "imported_at": item.imported_at,
        }
        for item in rows
    ]


def list_local_cves(db: Session, search: str = "", limit: int = 100) -> list[dict[str, Any]]:
    query = select(LocalCve)
    if search:
        query = query.where(LocalCve.cve_id.ilike(f"%{search}%"))
    rows = db.scalars(query.order_by(LocalCve.cvss_score.desc()).limit(limit)).all()
    return [
        {
            "cve_id": item.cve_id,
            "source": item.source,
            "severity": item.severity,
            "cvss_score": item.cvss_score,
            "published": item.published,
            "modified": item.modified,
            "description": item.description,
        }
        for item in rows
    ]
