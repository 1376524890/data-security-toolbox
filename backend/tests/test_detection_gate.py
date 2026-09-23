r"""A probe's score is a claim; the platform re-derives it before it becomes a finding.

A probe reports a category with the confidence *its* rule set gave it. A Presidio
recognizer that scored its own ``\b\d{6}[-]?\d{4}\b`` at 0.6 raised 331 Swedish
organisation numbers as findings, and a probe keeps reporting the score it was
shipped with long after the rule behind it was tightened. Everything here pins
the platform's answer instead: what would *these* rules say about this evidence?
"""
from __future__ import annotations

import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models import Detection
from app.services import detection_gate, rule_library

#: The rule that produced the incident, at the score its own pack reported.
ORGANISATION_NUMBER_PATTERN = r"\b\d{6}[-]?\d{4}\b"


def _h(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _register_probe(client: TestClient, name: str, ip: str = "10.9.7.1") -> tuple[int, str]:
    response = client.post("/api/v1/probes/register",
                           json={"name": name, "hostname": name, "ip_address": ip,
                                 "metadata": {}})
    assert response.status_code == 200
    body = response.json()
    return body["id"], body["token"]


def _headers(probe_id: int, token: str) -> dict[str, str]:
    return {"X-Probe-ID": str(probe_id), "X-Probe-Token": token}


def _hit(category: str, *, count: int = 2, rules=("SD_PHONE_001",), confidence: float = 0.9,
         evidence_types=("regex",)) -> dict:
    """A hit exactly as a probe writes it: the claim, with its rule named."""
    return {
        "entity": category.upper(), "category": category, "count": count,
        "confidence": confidence, "level": "L2", "severity": "Medium", "field_only": False,
        "rule_ids": list(rules), "rule_sources": ["builtin"],
        "evidence": [{"rule_id": rule, "entity": category.upper(),
                      "evidence_type": kind, "confidence": confidence,
                      "rule_source": "builtin"}
                     for rule in rules for kind in evidence_types],
        "field_name": "", "sheet_name": "", "matches": [],
    }


def _file(path: str, *, categories=("phone",), counts=None, hits=None) -> dict:
    evidence = {"extension": ".csv", "coverage": "complete", "termination_reason": "complete",
                "sample_rows": 25, "rows_read": 12,
                "hits": hits if hits is not None else [_hit("phone")]}
    return {"name": path.rsplit("/", 1)[-1], "asset_type": "table", "sensitivity": "Medium",
            "path": path, "size": 2048, "sha256": _h(path),
            "modified_at": "2026-09-15T00:00:00+00:00", "categories": list(categories),
            "counts": counts if counts is not None else {c: 2 for c in categories},
            "columns": [], "evidence": evidence}


def _report(report_id: str, assets: list[dict], **extra) -> dict:
    payload = {"report_id": report_id, "schema_version": "1.1", "scan_id": report_id,
               "assets": assets, "databases": [], "scanned_paths": ["/srv/data"], "max_depth": 3,
               "complete": True, "observed_at": "2026-09-15T00:00:00+00:00",
               "scanner": "probe-file-inventory",
               "coverage": {"complete_scope": True, "max_files": 200},
               "budget": {"files_analyzed": len(assets), "max_files": 200},
               "ruleset_version": "builtin-1", "engine_version": "1.0.0"}
    payload.update(extra)
    return payload


def _post(client: TestClient, probe_id: int, token: str, payload: dict):
    return client.post(f"/api/v1/probes/{probe_id}/data-assets", json=payload,
                       headers=_headers(probe_id, token))


def _detections_for(probe_id: int) -> list[Detection]:
    from sqlalchemy import select

    from app.models import AssetInstance

    with SessionLocal() as db:
        paths = db.scalars(select(AssetInstance.id).where(
            AssetInstance.owner_key == f"probe:{probe_id}")).all()
        if not paths:
            return []
        return list(db.scalars(select(Detection).where(Detection.instance_id.in_(paths))).all())


@pytest.fixture
def store_rules():
    """Rules written into the (isolated) rule store, removed when the test ends.

    The store is process-wide and other tests read it, so a fixture that always
    cleans up keeps this file from changing what they see.
    """
    written: list = []

    def write(*rules: dict) -> list[str]:
        path = rule_library.rule_store_directory() / f"gate-{uuid.uuid4().hex}.json"
        rule_library.atomic_json(path, {"rules": list(rules)})
        written.append(path)
        return [str(rule["id"]) for rule in rules]

    yield write
    for path in written:
        path.unlink(missing_ok=True)


# --- what one rule says about one kind of evidence --------------------------
def test_only_value_level_evidence_carries_a_rule_s_precision() -> None:
    rule = {"confidence": 0.85}
    assert detection_gate.confidence_for(rule, "regex") == 0.85
    assert detection_gate.confidence_for(rule, "validator") == 0.85
    # A column that is merely *named* for personal data is not a column that holds
    # any: the header and keyword evidence stay under the confirm threshold.
    for kind in ("field_name", "keyword", "context"):
        assert detection_gate.confidence_for(rule, kind) < detection_gate.confirm_threshold()


def test_nothing_to_judge_is_not_a_verdict() -> None:
    assert detection_gate.derived_confidence("phone", []) is None
    rows = [{"category": "phone", "rule_id": "a-rule-this-platform-lost",
             "evidence_type": "regex"}]
    # A rule the platform no longer holds is not proof the value was wrong, so the
    # report keeps its own score rather than being demoted by losing a rule.
    assert detection_gate.derived_confidence("phone", rows) is None


def test_a_pack_rule_in_the_store_is_read_at_the_platform_s_capped_score(store_rules) -> None:
    (rule_id,) = store_rules({
        "id": "presidio-gate-orgnr", "name": "SeOrganisationsnummerRecognizer",
        "entity": "SE_ORGANISATIONSNUMMER", "pattern": ORGANISATION_NUMBER_PATTERN,
        "confidence": 0.6, "source": "Presidio", "enabled": True,
    })

    rule = detection_gate.current_rules()[rule_id]

    # The pack scored its own pattern 0.6; the platform reads it at the digit-only
    # cap, which is what stops it from confirming anything.
    assert rule["confidence"] == rule_library.DIGIT_ONLY_CONFIDENCE
    assert not detection_gate.is_confirmed(rule["confidence"])


# --- what the ingest does with a report -------------------------------------
def test_a_category_only_a_pack_could_confirm_never_becomes_a_finding(store_rules) -> None:
    (rule_id,) = store_rules({
        "id": "presidio-gate-orgnr", "name": "SeOrganisationsnummerRecognizer",
        "entity": "SE_ORGANISATIONSNUMMER", "pattern": ORGANISATION_NUMBER_PATTERN,
        "confidence": 0.6, "source": "Presidio", "enabled": True,
    })
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "gate-demote-probe")
        asset = _file("/srv/gate/history.sh", categories=("se_organisationsnummer",),
                      counts={"se_organisationsnummer": 3},
                      hits=[_hit("se_organisationsnummer", count=3, rules=(rule_id,),
                                 confidence=0.6)])
        assert _post(client, probe_id, token, _report("r-gate-demote", [asset])).status_code == 200

        assert _detections_for(probe_id) == []
        # The claim is not thrown away: the operator still sees that a number
        # looked like an organisation number, it is just no longer discovered data.
        rows = client.get(f"/api/v1/data/assets?probe_id={probe_id}").json()["items"]
        row = next(item for item in rows if item["path"] == "/srv/gate/history.sh")
        assert row["categories"] == []
        assert row["candidate_categories"] == ["se_organisationsnummer"]


def test_a_confirmed_hit_is_stored_at_the_platform_s_score_not_the_report_s() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "gate-score-probe")
        asset = _file("/srv/gate/phones.csv", categories=("phone",), counts={"phone": 2},
                      hits=[_hit("phone", rules=("SD_PHONE_001",), confidence=0.99)])
        assert _post(client, probe_id, token, _report("r-gate-score", [asset])).status_code == 200

        rows = _detections_for(probe_id)
        assert [row.category for row in rows] == ["phone"]
        # 0.99 was the report's claim; 0.7 is what this platform's rule says.
        assert rows[0].confidence == 0.7


def test_a_hit_naming_a_rule_the_platform_lost_keeps_its_reported_score() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "gate-unknown-rule-probe")
        asset = _file("/srv/gate/legacy.csv", categories=("phone",), counts={"phone": 2},
                      hits=[_hit("phone", rules=("vendor-rule-that-is-gone",),
                                 confidence=0.75)])
        assert _post(client, probe_id, token, _report("r-gate-legacy", [asset])).status_code == 200

        rows = _detections_for(probe_id)
        assert [row.category for row in rows] == ["phone"]
        assert rows[0].confidence == 0.75
