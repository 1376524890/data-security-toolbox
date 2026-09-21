"""Rule matching for one sampled table, through the shared engine.

The output is deliberately the same *shape* the probe report uses for its hits
(rule ids, level, severity, evidence entries, bounded ``matches``), so the
existing evidence writer stores a database finding exactly like a file finding
and the same API/UI can explain both.

A column is scanned as its own text block with the column name as
``field_name``: a value-level hit stays confirmed, while a header-only clue such
as an empty ``phone`` column stays a candidate and never marks the table.
"""

from __future__ import annotations

from typing import Any

from app.services import sensitive_engine

#: Same ceiling the probe applies before a hit is allowed into a report.
MAX_EVIDENCE_ENTRIES = 32


def scan_table(sample: dict[str, Any]) -> dict[str, Any]:
    """Scan one table sample; returns hits, per-column rows and category totals."""
    # The console's own rules are part of the scan: a keyword an analyst added
    # for the network DLP stage is also what a database column is checked for.
    engine = sensitive_engine.scan_engine()
    table = str(sample.get("table") or "")
    hits: list[dict[str, Any]] = []
    columns: list[dict[str, Any]] = []
    categories: list[str] = []
    candidates: list[str] = []
    counts: dict[str, int] = {}
    summary: dict[str, dict[str, Any]] = {}
    for index, column in enumerate(sample.get("columns") or []):
        name = str(column.get("name") or "")
        values = (sample.get("values") or {}).get(name) or []
        results = engine.scan(
            sensitive_engine.SensitiveDetectionContext(
                text="\n".join(values), field_name=name, sheet_name=table,
                source_type="database",
            )
        )
        confirmed: list[str] = []
        local_candidates: list[str] = []
        for hit in results:
            if not hit.sensitive:
                continue
            category = sensitive_engine.legacy_name(hit.entity) or hit.entity.lower()
            if not category:
                continue
            if hit.count and hit.confirmed:
                if category not in confirmed:
                    confirmed.append(category)
                counts[category] = counts.get(category, 0) + hit.count
                if category not in categories:
                    categories.append(category)
                current = summary.get(category)
                if current is None or hit.confidence > current["confidence"]:
                    summary[category] = {"confidence": hit.confidence, "severity": hit.severity,
                                         "level": hit.level}
            # Anything a value did not confirm is inference: a field name, a
            # keyword, or a candidate that failed its validator. It is recorded
            # per column and never becomes a detection on its own.
            elif category not in confirmed and category not in local_candidates:
                local_candidates.append(category)
                if category not in categories and category not in candidates:
                    candidates.append(category)
        hits.extend(_hit_rows(results, column=column, name=name, index=index, table=table))
        columns.append({
            "name": name,
            "type": str(column.get("type") or ""),
            "sample_size": int(column.get("sample_size") or 0),
            "nulls": int(column.get("nulls") or 0),
            "sensitivity": "High" if confirmed else "Unknown",
            "confirmed_categories": confirmed,
            "candidate_categories": local_candidates,
            "categories": confirmed + local_candidates,
        })
    return {
        "table": table,
        "schema": str(sample.get("schema") or ""),
        "rows_read": int(sample.get("rows_read") or 0),
        "hits": hits,
        "columns": columns,
        "categories": categories,
        "candidates": candidates,
        "counts": counts,
        "summary": summary,
    }


def _hit_rows(hits, *, column: dict[str, Any], name: str, index: int,
              table: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for hit in hits:
        if not hit.count:
            continue
        rows.append({
            "entity": hit.entity,
            "category": sensitive_engine.legacy_name(hit.entity) or hit.entity.lower(),
            "count": hit.count,
            "confidence": hit.confidence,
            "confirmed": hit.confirmed,
            "field_only": hit.field_only,
            "level": hit.level,
            "severity": hit.severity,
            "rule_ids": list(hit.rule_ids),
            "rule_sources": list(hit.rule_sources),
            "evidence": [item.to_dict() for item in hit.evidence][:MAX_EVIDENCE_ENTRIES],
            # 原文 the engine returned for this hit, already capped by the engine.
            "matches": [dict(item) for item in hit.matches],
            "field_name": name,
            "sheet_name": table,
            "column_index": index,
        })
    return rows
