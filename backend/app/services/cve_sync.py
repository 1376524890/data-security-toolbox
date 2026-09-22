"""Fetch CVE rules for the products the platform actually fingerprinted.

The local CVE library is what ``ThreatIntelEngine`` matches a scanned service
against; an empty library means a scan can never confirm a vulnerability. This
module fills it two ways from one place:

* ``fingerprints`` lists the distinct products/services nmap ``-sV`` and the
  built-in banner grabber reported, so the update targets this environment
  instead of pulling the whole NVD.
* ``sync`` queries the NVD 2.0 API per fingerprint and imports the records
  through the canonical importer, which keeps the CPE product and the affected
  version interval — the only thing that lets a hit be *confirmed* rather than
  reported as a lead.
"""
from __future__ import annotations

from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrations.offline_manager import import_cve_record
from app.models import Asset

#: NVD's public search endpoint; the same default the threat-intel rule carries.
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
#: How many fingerprints one update touches. A scan of a /24 yields a handful,
#: and NVD rate-limits anonymous callers to ~5 requests / 30s.
MAX_FINGERPRINTS = 20
RESULTS_PER_FINGERPRINT = 50
REQUEST_TIMEOUT = 30


def _usable(name: str) -> bool:
    """Whether a fingerprint is worth querying NVD for.

    Generic service names ("http", "unknown") return thousands of unrelated
    CVEs and would poison the library with false leads.
    """
    cleaned = str(name or "").strip()
    return len(cleaned) >= 3 and cleaned.lower() not in _GENERIC


_GENERIC = {"http", "https", "unknown", "tcp", "ssl", "tls", "upnp", "finger",
            "msrpc", "netbios-ssn", "netbios-ns", "domain", "general purpose"}


def fingerprints(db: Session) -> list[str]:
    """Distinct product (or service) names the platform has fingerprinted."""
    products = db.scalars(select(Asset.extra["product"].as_string()).distinct()).all()
    services = db.scalars(select(Asset.service).distinct()).all()
    wanted: list[str] = []
    for candidate in [*(products or []), *(services or [])]:
        name = str(candidate or "").strip()
        if _usable(name) and name not in wanted:
            wanted.append(name)
    return wanted


def fetch_nvd(keyword: str, per_page: int = RESULTS_PER_FINGERPRINT,
              api_key: str = "") -> list[dict[str, Any]]:
    """The raw NVD records for one keyword; raises on a transport/HTTP error."""
    headers = {"apiKey": api_key} if api_key else {}
    response = requests.get(
        NVD_URL, params={"keywordSearch": keyword, "resultsPerPage": per_page},
        headers=headers, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return list(response.json().get("vulnerabilities") or [])


def sync(db: Session, keywords: list[str] | None = None,
         per_page: int = RESULTS_PER_FINGERPRINT) -> dict[str, Any]:
    """Update the local CVE library for the given (or fingerprinted) products."""
    targets = [item for item in (keywords or fingerprints(db)) if _usable(item)][:MAX_FINGERPRINTS]
    imported = updated = 0
    errors: list[str] = []
    for keyword in targets:
        try:
            records = fetch_nvd(keyword, per_page)
        except Exception as exc:  # transport, HTTP status, malformed JSON
            errors.append(f"{keyword}: {exc}")
            continue
        for record in records:
            cve_id = str(((record or {}).get("cve") or {}).get("id") or "")
            known = _has_cve(db, cve_id)
            if import_cve_record(db, record):
                if known:
                    updated += 1
                else:
                    imported += 1
        db.commit()
    return {"keywords": targets, "imported": imported, "updated": updated, "errors": errors}


def _has_cve(db: Session, cve_id: str) -> bool:
    from app.models import LocalCve

    if not cve_id:
        return False
    return db.scalar(select(LocalCve.id).where(LocalCve.cve_id == cve_id)) is not None
