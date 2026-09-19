"""Shared Incident-row serialisation used by more than one route domain."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.datetimes import aware
from app.models import Incident


def serialize_incident(item: Incident) -> dict[str, Any]:
    findings = item.findings or {}
    if isinstance(findings, dict) and isinstance(findings.get("items"), list):
        enriched_items: list[Any] = []
        uploads_root = (settings.storage_dir / "uploads").resolve()
        for finding in findings["items"]:
            if not isinstance(finding, dict):
                enriched_items.append(finding)
                continue
            evidence = finding.get("evidence")
            if not isinstance(evidence, dict) or not isinstance(evidence.get("file"), str):
                enriched_items.append(finding)
                continue
            evidence_copy = dict(evidence)
            try:
                evidence_path = Path(evidence["file"]).resolve()
                if evidence_path.is_relative_to(uploads_root) and evidence_path.is_file():
                    raw = evidence_path.read_bytes()[:20000]
                    evidence_copy["raw_text"] = raw.decode("utf-8-sig", "replace")
                    evidence_copy["raw_text_truncated"] = evidence_path.stat().st_size > len(raw)
            except (OSError, ValueError):
                pass
            enriched_items.append({**finding, "evidence": evidence_copy})
        findings = {**findings, "items": enriched_items}
    return {
        "id": item.id,
        "fingerprint": item.fingerprint,
        "probe_id": item.probe_id,
        "source": item.source,
        "title": item.title,
        "severity": item.severity,
        "confidence": item.confidence,
        "status": item.status,
        "findings": findings,
        "evidence": item.evidence,
        "risk_score": item.risk_score,
        "risk_level": item.risk_level,
        "timestamp": item.timestamp,
        "last_seen": aware(item.last_seen),
        "occurrence_count": item.occurrence_count,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }
