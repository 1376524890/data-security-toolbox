"""The fingerprint → CVE path has to survive the import round trip.

A scanned service becomes a finding only when the library carries the affected
version interval; a record flattened into free text can never do more than raise
an unconfirmed lead. These tests pin both halves: what the import keeps, and what
the engine does with it.
"""
from sqlalchemy import delete

from app.core.database import SessionLocal
from app.integrations.offline_manager import (
    _cpe_version_spec,
    _structured_versions,
    import_cve_records,
)
from app.models import Asset, LocalCve
from app.services import cve_sync

# One NVD 2.0 record, trimmed to the fields the importer reads.
NVD_HTTPD = {
    "cve": {
        "id": "CVE-2099-0001",
        "published": "2099-01-01T00:00:00.000",
        "lastModified": "2099-02-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Apache httpd before 2.4.60 allows request smuggling."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "2.4.0",
            "versionEndExcluding": "2.4.60",
        }]}]}],
    },
}


def test_a_nvd_record_keeps_its_product_and_affected_range():
    structured = _structured_versions(NVD_HTTPD, NVD_HTTPD["cve"])
    assert structured["product"] == "httpd"
    assert structured["affected_versions"] == [">=2.4.0,<2.4.60"]


def test_an_unbounded_cpe_keeps_the_product_but_claims_no_range():
    """No interval ⇒ the record must stay a lead, not become a false positive."""
    record = {"cve": {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}]}]}]}}
    assert _structured_versions(record, record["cve"]) == {"product": "nginx"}


def test_a_pinned_cpe_version_becomes_an_equality_spec():
    entry = {"criteria": "cpe:2.3:a:openssh:openssh:8.2p1:*:*:*:*:*:*:*"}
    assert _cpe_version_spec(entry, entry["criteria"]) == "==8.2p1"


def test_import_round_trip_keeps_the_range_and_derives_the_level():
    with SessionLocal() as db:
        db.execute(delete(LocalCve).where(LocalCve.cve_id == "CVE-2099-0001"))
        db.commit()
        imported, _duplicates = import_cve_records(db, [NVD_HTTPD])
        db.commit()
        assert imported == 1
        row = db.query(LocalCve).filter(LocalCve.cve_id == "CVE-2099-0001").one()
    assert row.severity == "Critical"          # from the 9.8 score, not "Medium"
    assert row.cvss_score == 9.8
    assert row.description["product"] == "httpd"
    assert row.description["affected_versions"] == [">=2.4.0,<2.4.60"]


def test_the_engine_confirms_a_version_inside_the_imported_range():
    from app.threat_intel.engine import ThreatIntelEngine

    engine = ThreatIntelEngine()
    # "Apache httpd" is what nmap prints; the library indexes "httpd".
    hits = engine._local_cve_lookup("Apache httpd 2.4.68", 10, "Apache httpd")
    assert [hit["cve_id"] for hit in hits] == ["CVE-2099-0001"]
    affected, reason = engine._version_affected("2.4.59", hits[0])
    assert affected is True and reason == "matched_declared_range"
    # 2.4.68 is *outside* the range the record declares, so it must be dropped
    # rather than reported: a known-unaffected version is a false positive.
    affected, reason = engine._version_affected("2.4.68", hits[0])
    assert affected is False and reason == "outside_declared_range"


# CVE-2016-0746 in the shape NVD publishes it: the vulnerable nginx range sits
# next to bounds that belong to entirely different products.
NVD_MIXED_PRODUCTS = {
    "cve": {
        "id": "CVE-2099-0002",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "0.6.18", "versionEndIncluding": "1.8.0"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "1.9.0", "versionEndExcluding": "1.9.10"},
            {"vulnerable": True, "criteria": "cpe:2.3:o:apple:xcode:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "13.0"},
            {"vulnerable": True, "criteria": "cpe:2.3:o:canonical:ubuntu_linux:14.04:*:*:*:esm:*:*:*"},
        ]}]}],
    },
}


def test_ranges_do_not_leak_across_the_products_in_one_record():
    """Another product's bound must not confirm the scanned product.

    NVD lists every product a configuration covers; flattening them let the
    xcode ``<13.0`` bound confirm ``nginx 1.27.5`` against a 2016 CVE.
    """
    structured = _structured_versions(NVD_MIXED_PRODUCTS, NVD_MIXED_PRODUCTS["cve"])
    assert structured["product"] == "nginx"
    assert structured["affected_versions"] == [">=0.6.18,<=1.8.0", ">=1.9.0,<1.9.10"]
    assert structured["product_ranges"]["xcode"] == ["<13.0"]

    from app.threat_intel.engine import ThreatIntelEngine

    engine = ThreatIntelEngine()
    hit = {"affected_versions": structured["affected_versions"]}
    assert engine._version_affected("1.27.5", hit) == (False, "outside_declared_range")
    assert engine._version_affected("1.6.0", hit) == (True, "matched_declared_range")


def test_an_unparsable_constraint_cannot_confirm_by_default():
    """A skipped constraint made the AND chain vacuously true.

    ``==3.7.1p1`` used to drop out of the loop, so OpenSSH 8.2p1 "matched" a
    CVE that only lists 3.7.1.
    """
    from app.threat_intel.engine import ThreatIntelEngine

    engine = ThreatIntelEngine()
    assert engine._version_affected("8.2p1", {"affected_versions": ["==3.7.1p1"]})[0] is False
    assert engine._version_affected("3.7.1p1", {"affected_versions": ["==3.7.1p1"]})[0] is True
    assert engine._version_affected("8.2p1", {"affected_versions": ["==3.7.1"]})[0] is False


def test_fingerprints_skip_generic_service_names_but_keep_products():

    with SessionLocal() as db:
        db.execute(delete(Asset).where(Asset.ip == "10.255.255.7"))
        db.add(Asset(ip="10.255.255.7", port=8080, service="http",
                     extra={"source": "platform_scan", "product": "nginx", "version": "1.27.5"}))
        db.add(Asset(ip="10.255.255.7", port=9090, service="http",
                     extra={"source": "platform_scan", "product": "", "version": ""}))
        db.commit()
        found = cve_sync.fingerprints(db)
        db.execute(delete(Asset).where(Asset.ip == "10.255.255.7"))
        db.commit()
    assert "nginx" in found
    # "http" alone would pull thousands of unrelated records.
    assert not [item for item in found if item.lower() in {"http", "https", "unknown"}]


def test_the_sync_endpoint_reports_the_fingerprints_it_would_query(monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app
    from app.services import cve_sync as module

    monkeypatch.setattr(module, "fetch_nvd", lambda keyword, per_page=0, api_key="": [NVD_HTTPD])
    with SessionLocal() as db:
        db.execute(delete(Asset).where(Asset.ip == "10.255.255.8"))
        db.add(Asset(ip="10.255.255.8", port=80, service="http",
                     extra={"source": "platform_scan", "product": "Apache httpd", "version": "2.4.68"}))
        db.commit()
    with TestClient(app) as client:
        targets = client.get("/api/v1/offline/cves/fingerprints").json()["fingerprints"]
        assert "Apache httpd" in targets
        body = client.post("/api/v1/offline/cves/sync", json={"keywords": ["Apache httpd"]}).json()
    assert body["keywords"] == ["Apache httpd"]
    assert body["imported"] + body["updated"] >= 1
    with SessionLocal() as db:
        db.execute(delete(Asset).where(Asset.ip == "10.255.255.8"))
        db.commit()
