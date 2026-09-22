"""Contract checks for the six read-only assessment endpoints."""
from fastapi.testclient import TestClient

from app.main import app

KINDS = ("overview", "classification", "exposure", "flow", "egress", "compliance")


def test_every_assessment_returns_the_five_segment_envelope() -> None:
    with TestClient(app) as client:
        for kind in KINDS:
            response = client.get(f"/api/v1/assessments/{kind}")
            assert response.status_code == 200, f"{kind}: {response.text}"
            body = response.json()
            assert body["title"] and body["conclusion"]
            assert body["kpis"], kind
            # Every metric card carries a denominator and a coverage boundary.
            assert all(item["denominator"] is not None for item in body["kpis"])
            assert body["caliber"]["notes"]
            assert body["caliber"]["tls_decryption"] is False
            assert isinstance(body["gaps"], list)


def test_assessments_never_look_clean_without_the_region_table(monkeypatch) -> None:
    """No region table ⇒ egress degrades to “无法判定”, never “无出境”.

    The shipped table is present, so the degrade path is forced here rather than
    relying on the deployment having no data.
    """
    from app.services import egress_regions

    monkeypatch.setattr(egress_regions, "country_table", lambda path=None: {"regions": {}})
    egress_regions.reset_country_ranges()
    try:
        with TestClient(app) as client:
            body = client.get("/api/v1/assessments/egress").json()
        assert body["caliber"]["region_table_present"] is False
        assert "无法判定" in body["conclusion"]
    finally:
        egress_regions.reset_country_ranges()
