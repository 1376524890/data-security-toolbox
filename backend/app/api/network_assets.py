# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""网络资产: the ports a scan found, with the CVEs their fingerprints matched.

Scan results used to be readable only through the single task that produced
them (``GET /scan/{task_id}``), so the inventory disappeared as soon as the
operator looked at another task. This module exposes the same rows as a standing
inventory: one row per scanned service, each carrying the CVE findings the
threat-intel engine matched against its product/version.

Nothing is computed twice: rows come from ``assets`` (``extra->source`` in
platform_scan / nmap_scan / probe_scan), the CVE hits come from the findings the
pipeline already stored, and the row shape reuses
``api/assets.py::serialize_asset``.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.assets import serialize_asset
from app.api.list_sort import order_rows
from app.api.pagination import page_response
from app.core.database import get_db
from app.models import Asset, DetectionFinding

router = APIRouter()

#: The sources an active scan writes. A probe's own inventory is a different
#: collection path and is not part of "what the scan found".
SCAN_SOURCES = ("platform_scan", "nmap_scan", "probe_scan")

#: CVE findings are keyed by rule id; the engine also emits CVE_CANDIDATE_001
#: for keyword leads. Both are shown, but a lead stays visibly unconfirmed.
CVE_RULE_PREFIX = "CVE"

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Unknown")

#: How many recent CVE findings to fold in. A scan produces a bounded number of
#: hosts, and the rows are grouped by asset below.
FINDING_WINDOW = 5000


def _asset_key(ip: str, port: int) -> tuple[str, int]:
    return (str(ip or ""), int(port or 0))


def cve_findings_by_asset(db: Session) -> dict[tuple[str, int], list[dict[str, Any]]]:
    """Group the stored CVE findings by the (ip, port) they were raised for.

    The engine records the matched service in ``evidence.asset``; that service
    dict is what carries the ip/port, so the grouping needs no new column and no
    second matching pass.
    """
    rows = db.scalars(
        select(DetectionFinding)
        .where(DetectionFinding.rule_id.ilike(f"{CVE_RULE_PREFIX}%"))
        .order_by(DetectionFinding.id.desc())
        .limit(FINDING_WINDOW)
    ).all()
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = {}
    # "CVE_CVE-2024-1234" is the confirmed rule id the engine emits; anything
    # else under the prefix (CVE_CANDIDATE_001) has no single CVE behind it.
    id_pattern = re.compile(r"CVE-\d{4}-\d{4,}")
    for row in rows:
        evidence = row.evidence or {}
        derived = row.rule_id[len(CVE_RULE_PREFIX) + 1:]
        # A lead finding packs several (cve, asset) pairs under the one
        # CVE_CANDIDATE_* rule id. Each pair is its own row, otherwise the
        # drawer shows anonymous "candidate" lines with no CVE behind them.
        pairs = [(item.get("cve") or {}, item.get("asset") or {})
                 for item in (evidence.get("candidates") or [])]
        if not pairs and evidence.get("cve"):
            pairs = [(evidence["cve"], evidence.get("asset") or {})]
        for cve, target in pairs:
            key = _asset_key(target.get("ip"), target.get("port") or 0)
            if not key[0]:
                continue
            hit = {
                "rule_id": row.rule_id,
                "cve_id": str(cve.get("cve_id")
                              or (derived if id_pattern.fullmatch(derived) else "")),
                "severity": str(cve.get("severity") or row.severity),
                "cvss_score": cve.get("cvss_score") or 0,
                "confidence": row.confidence,
                "confirmed": bool(evidence.get("confirmed")),
                "match_reason": evidence.get("match_reason") or evidence.get("note") or "",
                "library_source": cve.get("source") or evidence.get("library_source") or "",
                "recommendation": row.recommendation,
                "finding_id": row.id,
            }
            # Rows are read newest first, so the first hit for a rule is the
            # current one. Every scan re-raises the same rules for the same
            # port, and repeating them per scan turned one CVE into a list.
            bucket = grouped.setdefault(key, [])
            if not any(existing["rule_id"] == hit["rule_id"]
                       and existing["cve_id"] == hit["cve_id"] for existing in bucket):
                bucket.append(hit)
    return grouped


def _row(asset: Asset, hits: list[dict[str, Any]]) -> dict[str, Any]:
    extra = asset.extra or {}
    confirmed = [hit for hit in hits if hit["confirmed"]]
    scores = [float(hit.get("cvss_score") or 0) for hit in hits] or [0.0]
    return {
        **serialize_asset(asset),
        "source": str(extra.get("source") or ""),
        "product": str(extra.get("product") or ""),
        "version": str(extra.get("version") or ""),
        "banner": str(extra.get("banner") or ""),
        "tls": extra.get("tls") or {},
        "public_exposed": bool(extra.get("public_exposed")),
        "cves": hits,
        "cve_count": len(hits),
        "confirmed_cve_count": len(confirmed),
        "max_cvss": max(scores),
    }


#: Whitelisted sort keys. Rows are merged with their CVE hits in Python, so the
#: sort is applied there too; the natural order (weakest CVSS first) is untouched
#: when the caller asks for nothing.
NETWORK_ASSET_SORTABLE = {
    "ip": lambda row: row["ip"], "port": lambda row: row["port"],
    "service": lambda row: row["service"], "product": lambda row: row["product"],
    "version": lambda row: row["version"], "source": lambda row: row["source"],
    "risk_level": lambda row: row["risk_level"], "cve_count": lambda row: row["cve_count"],
    "confirmed_cve_count": lambda row: row["confirmed_cve_count"],
    "max_cvss": lambda row: row["max_cvss"], "last_seen": lambda row: row["last_seen"],
}


@router.get("/network/assets")
def network_assets(
    search: str | None = None,
    severity: str | None = None,
    only_vulnerable: bool = False,
    source: str | None = None,
    order_by: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """The scanned-service inventory with its matched CVEs, newest first."""
    query = select(Asset).where(Asset.extra["source"].as_string().in_(SCAN_SOURCES))
    if source:
        query = query.where(Asset.extra["source"].as_string() == source)
    if search:
        needle = f"%{search}%"
        query = query.where(or_(
            Asset.ip.ilike(needle), Asset.hostname.ilike(needle),
            Asset.service.ilike(needle), Asset.extra["product"].as_string().ilike(needle),
            Asset.extra["version"].as_string().ilike(needle),
        ))
    rows = db.scalars(query.order_by(Asset.ip, Asset.port)).all()
    grouped = cve_findings_by_asset(db)
    items = [_row(asset, grouped.get(_asset_key(asset.ip, asset.port), [])) for asset in rows]
    if severity:
        wanted = severity.lower()
        items = [item for item in items
                 if any(str(hit["severity"]).lower() == wanted for hit in item["cves"])]
    if only_vulnerable:
        items = [item for item in items if item["cve_count"]]
    items.sort(key=lambda item: (-item["max_cvss"], item["ip"], item["port"]))
    if order_by:
        items = order_rows(items, order_by, NETWORK_ASSET_SORTABLE,
                           default="max_cvss", default_desc=True)
    total = len(items)
    start = (page - 1) * page_size
    return page_response(items[start:start + page_size], page, page_size, total)


@router.get("/network/assets/summary")
def network_assets_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Counts for the header cards, always with the denominator they came from."""
    rows = db.scalars(
        select(Asset).where(Asset.extra["source"].as_string().in_(SCAN_SOURCES))
    ).all()
    grouped = cve_findings_by_asset(db)
    services = len(rows)
    hosts = len({asset.ip for asset in rows})
    by_severity = dict.fromkeys(SEVERITY_ORDER, 0)
    cve_ids: set[str] = set()
    vulnerable_hosts: set[str] = set()
    confirmed = 0
    for asset in rows:
        hits = grouped.get(_asset_key(asset.ip, asset.port), [])
        if hits:
            vulnerable_hosts.add(asset.ip)
        for hit in hits:
            if hit["confirmed"]:
                confirmed += 1
            if hit["cve_id"]:
                cve_ids.add(str(hit["cve_id"]))
            level = str(hit["severity"] or "Unknown")
            by_severity[level] = by_severity.get(level, 0) + 1
    return {
        "assets": len(rows), "hosts": hosts, "services": services,
        "vulnerable_hosts": len(vulnerable_hosts), "cves": len(cve_ids),
        "confirmed_hits": confirmed,
        "by_severity": [{"severity": level, "count": by_severity[level]}
                        for level in SEVERITY_ORDER if by_severity.get(level)],
        "sources": sorted({str((asset.extra or {}).get("source") or "") for asset in rows} - {""}),
    }
