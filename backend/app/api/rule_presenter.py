"""Authored-rule lookup shared by the alert console and the rule catalogue."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import LocalCve, OfflineResource, SystemSetting
from app.rules import library
from app.rules.catalog import CATALOG
from app.services.rule_library import rule_store_files


def rule_file_entries(
    db: Session, engine: str = "", include_content: bool = True
) -> list[dict[str, Any]]:
    """Every rule file the platform library holds, with its engine and content.

    The directories come from ``app.rules.catalog`` so the rule list, the rule
    count and the files the engines actually load can never disagree. Files
    imported at runtime (data/integrations/...) are listed on top of the ones
    shipped with the platform.
    """
    items: list[dict[str, Any]] = []

    def _add(path: Path, rtype: str, engine_name: str) -> None:
        if engine and engine != engine_name:
            return
        try:
            content = path.read_text(encoding="utf-8", errors="replace") if include_content else ""
        except Exception:
            content = ""
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        execution = "active"
        if engine_name in {"osquery", "wazuh", "openscap", "misp", "presidio"}:
            execution = "external"
        if engine_name == "zeek" and path.name != "site_security.zeek":
            execution = "external"
        if engine_name == "sigma_log_engine":
            from app.rules.sigma import load_sigma_rules

            if not load_sigma_rules(path):
                execution = "unsupported"
        if engine_name == "openscap" and path.name == "dst_baseline_xccdf.xml":
            execution = "incomplete"
        items.append(
            {
                "type": rtype,
                "engine": engine_name,
                "name": path.name,
                "path": str(path),
                "content": content if include_content else "",
                "size": size,
                "execution": execution,
            }
        )

    # ``library.rule_files`` resolves both the rule files shipped with the
    # platform and the ones an online refresh downloaded into the runtime dir.
    for source in CATALOG:
        if engine and source.engine != engine:
            continue
        for path in library.rule_files(source.engine):
            _add(path, source.rule_type, source.engine)
    # Operator-imported libraries live under the runtime integration directory.
    for path in sorted((settings.integration_dir / "yara_rules").glob("*.yar")):
        _add(path, "yara", "data_engine")
    for path in rule_store_files():
        _add(path, "dlp", "dlp_engine")
    for path in sorted((settings.integration_dir / "sigma_rules").glob("*.y*ml")):
        _add(path, "sigma", "sigma_log_engine")
    for path in sorted((settings.integration_dir / "suricata_rules").glob("*.rules")):
        _add(path, "suricata", "suricata")
    resources = db.scalars(
        select(OfflineResource).where(OfflineResource.resource_type == "suricata_rules")
    ).all()
    for resource in resources:
        path = Path(resource.storage_path)
        if path.exists() and path.is_file():
            _add(path, "suricata", "suricata")
        elif path.exists() and path.is_dir():
            for rule_file in sorted(path.glob("*.rules")):
                _add(rule_file, "suricata", "suricata")
    from app.rules.code_catalog import definitions

    for definition in definitions():
        if engine and definition["engine"] != engine:
            continue
        items.append(
            {
                "type": "builtin",
                "engine": definition["engine"],
                "name": definition["title"],
                "rule_id": definition["rule_id"],
                "path": definition["path"] + "#" + definition["rule_id"],
                "content": definition["content"] if include_content else "",
                "size": len(definition["content"].encode()),
                "execution": "active",
            }
        )
    return list({(item["engine"], item["path"]): item for item in items}.values())


def rule_definition(
    db: Session, rule_id: str, engine: str = "", evidence: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    """Find the authored definition of ``rule_id``.

    An alert must be able to show *which rule* matched, not only its id, so the
    lookup returns the rule's title, condition/recommendation and raw text along
    with where it lives. Three kinds of rule exist and all three are resolved:
    rule files in the platform library, code-implemented rules declared in
    ``app.rules.builtin``, and data-driven rules (the DLP policy, NVD records).
    """
    if not rule_id:
        return None
    evidence = evidence if isinstance(evidence, dict) else {}
    snapshot = evidence.get("rule_snapshot")
    if (
        isinstance(snapshot, dict)
        and snapshot.get("rule_id") == rule_id
        and snapshot.get("engine") == engine
    ):
        return {**snapshot, "resolution": "matched_snapshot"}
    # Stored DLP policy overrides the shipped defaults. Never let its YAML file
    # hide the actual configured policy in an alert.
    if rule_id == "DLP_TRANSFER_001":
        from app.rules.builtin import dlp_rule_definition
        from app.services.dlp import normalize_policy

        row = db.scalar(select(SystemSetting).where(SystemSetting.key == "dlp_policy"))
        return {
            **dlp_rule_definition(rule_id, normalize_policy(row.value if row else {})),
            "resolution": "current_definition",
        }
    configured = library.rule_snapshot(engine, rule_id) if engine else None
    if configured:
        return {**configured, "resolution": "current_definition"}
    # Imported here rather than at module scope so this optional parser stays off
    # the API import path.
    import yaml

    lookup_id = rule_id.removeprefix("SURICATA_") if engine == "suricata" else rule_id
    for item in rule_file_entries(db, engine=engine):
        content = str(item.get("content") or "")
        # Cheap prefilter: only parse the files that mention this rule id.
        if lookup_id not in content or item["type"] == "builtin":
            continue
        rtype = str(item.get("type") or "")
        definition: dict[str, Any] = {
            "rule_id": rule_id,
            "engine": str(item.get("engine") or ""),
            "type": rtype,
            "path": str(item.get("path") or ""),
            "file": str(item.get("name") or ""),
            "content": content,
            "title": "",
            "severity": "",
            "condition": "",
            "recommendation": "",
            "detection": None,
        }
        if rtype == "yara":
            if re.search(rf"^\s*rule\s+{re.escape(rule_id)}\b", content, re.MULTILINE):
                definition["title"] = rule_id
                return definition
            continue
        if rtype == "suricata":
            for line in content.splitlines():
                if not line.lstrip().startswith("#") and re.search(
                    rf"\bsid\s*:\s*{re.escape(lookup_id)}\s*;", line
                ):
                    title = re.search(r'msg\s*:\s*"([^"\n]+)"', line)
                    definition.update(
                        title=title.group(1) if title else rule_id,
                        content=line,
                        condition=line,
                        resolution="current_definition",
                    )
                    return definition
            continue
        try:
            document = yaml.safe_load(content)
        except Exception:
            continue
        for entry in document if isinstance(document, list) else [document]:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("rule_id") or entry.get("id") or "") != rule_id:
                continue
            definition.update(
                {
                    "title": str(entry.get("title") or rule_id),
                    "severity": str(entry.get("severity") or entry.get("level") or ""),
                    "condition": str(
                        entry.get("condition")
                        or (entry.get("detection") or {}).get("condition")
                        or ""
                    ),
                    "recommendation": str(entry.get("recommendation") or ""),
                    "detection": (
                        entry.get("detection") if isinstance(entry.get("detection"), dict) else None
                    ),
                }
            )
            return definition
    # No rule file carries this id: resolve the rules the engines apply
    # themselves, so an alert never renders an empty rule block.
    from app.rules import builtin as builtin_rules

    record: dict[str, Any] = {}
    if rule_id.startswith("CVE_"):
        row = db.scalar(select(LocalCve).where(LocalCve.cve_id == rule_id[4:]))
        if row:
            record = {
                "cve_id": row.cve_id,
                "severity": row.severity,
                "cvss_score": row.cvss_score,
                "published": row.published,
                "description": row.description,
            }
    definition = builtin_rules.cve_rule_definition(rule_id, evidence, record)
    if definition:
        return definition
    policy = None
    if rule_id == "DLP_TRANSFER_001":
        row = db.scalar(select(SystemSetting).where(SystemSetting.key == "dlp_policy"))
        from app.services.dlp import DEFAULT_POLICY, normalize_policy

        policy = normalize_policy(row.value if row else DEFAULT_POLICY)
    definition = builtin_rules.dlp_rule_definition(rule_id, policy)
    if definition:
        return definition
    return builtin_rules.builtin_rule_definition(rule_id)
