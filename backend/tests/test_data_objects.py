"""Object / instance / detection semantics, scope lifecycle and progress.

These tests pin the decisions that are easy to get subtly wrong and expensive to
get wrong in production: what may merge into one object, what may be declared
gone, what a late report may change, and what the legacy pages keep seeing.
"""
from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app
from app.models import (AssetInstance, DataAsset, DataObject, Detection, DetectionEvidence, Probe,
                        SystemSetting, Task)
from app.services import data_object_service as svc

PARTIAL_VERSION = "1.0.0"
# The test database is shared by the whole session, so every test derives its own
# digests: a hash is a global identity and reusing one across tests would merge
# unrelated fixtures on purpose.
def _h(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _register_probe(client: TestClient, name: str, ip: str = "10.9.9.9") -> tuple[int, str]:
    response = client.post("/api/v1/probes/register",
                           json={"name": name, "hostname": name, "ip_address": ip, "metadata": {}})
    assert response.status_code == 200
    body = response.json()
    return body["id"], body["token"]


def _headers(probe_id: int, token: str) -> dict[str, str]:
    return {"X-Probe-ID": str(probe_id), "X-Probe-Token": token}


def _hit(category: str, *, count: int = 2, rules=("SD_PHONE_001",), field: str = "",
         sheet: str = "", evidence_types=("regex",), matches=None) -> dict:
    return {
        "entity": category.upper(), "category": category, "count": count, "confidence": 0.9,
        "level": "L2", "severity": "Medium", "field_only": False,
        "rule_ids": list(rules), "rule_sources": ["builtin"],
        "evidence": [{"rule_id": rule, "entity": category.upper(),
                      "evidence_type": kind, "confidence": 0.9, "rule_source": "builtin"}
                     for rule in rules for kind in evidence_types],
        "field_name": field, "sheet_name": sheet,
        "matches": list(matches or []),
    }


def _file(path: str, *, sha: str = "", categories=("phone",), counts=None,
          hits=None, fingerprint=None, name=None, size=2048) -> dict:
    evidence = {"extension": ".csv", "coverage": "complete",
                "termination_reason": "complete", "sample_rows": 25,
                "inode": 42, "device": 7, "mtime_ns": 1710000000000000000,
                "owner": 0, "group": 0, "permission": "0o644",
                "hits": hits if hits is not None else [_hit("phone") for _ in range(1)]}
    if fingerprint is not None:
        evidence["fingerprint"] = fingerprint
    return {"name": name or path.rsplit("/", 1)[-1], "asset_type": "table",
            "sensitivity": "Medium", "path": path, "size": size, "sha256": sha,
            "modified_at": "2026-09-15T00:00:00+00:00",
            "categories": list(categories),
            "counts": counts if counts is not None else {c: 2 for c in categories},
            "columns": [], "evidence": evidence}


def _report(report_id: str, assets: list[dict], *, paths=("/srv/data",), complete=True,
            completed_scope=None, observed_at="2026-09-15T00:00:00+00:00",
            schema="1.1", scan_id="", **extra) -> dict:
    payload = {"report_id": report_id, "schema_version": schema,
               "scan_id": scan_id or report_id, "assets": assets, "databases": [],
               "scanned_paths": list(paths), "max_depth": 3, "complete": complete,
               "observed_at": observed_at, "scanner": "probe-file-inventory",
               "coverage": {"complete_scope": complete, "max_files": 200},
               "budget": {"files_analyzed": len(assets), "max_files": 200},
               "ruleset_version": "builtin-1", "engine_version": "1.0.0"}
    if completed_scope is not None:
        payload["completed_scope"] = completed_scope
    payload.update(extra)
    return payload


def _post(client: TestClient, probe_id: int, token: str, payload: dict):
    return client.post(f"/api/v1/probes/{probe_id}/data-assets", json=payload,
                       headers=_headers(probe_id, token))


# --- object identity --------------------------------------------------------
def test_equal_full_hash_forms_one_object_and_two_instances() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "identity-probe")
        same = _h("identity-1")
        assets = [_file("/srv/data/a.csv", sha=same), _file("/srv/other/b.csv", sha=same)]
        assert _post(client, probe_id, token, _report("r-identity", assets)).status_code == 200

        types = client.get(f"/api/v1/data-types?probe_id={probe_id}").json()
        phone = next(item for item in types["items"] if item["category"] == "phone")
        assert phone["object_count"] == 1
        assert phone["active_instance_count"] == 2
        assert phone["host_count"] == 1
        assert phone["confirmed_duplicate_count"] == 1
        assert phone["candidate_count"] == 0
        assert phone["level"] == "L2" and phone["severity"] == "Medium"
        assert types["dedup_rules"]["candidate_count"]

        objects = client.get(f"/api/v1/data-objects?probe_id={probe_id}").json()
        assert objects["total"] == 1
        obj = client.get(f"/api/v1/data-objects/{objects['items'][0]['id']}").json()
        assert obj["identity_confidence"] == 1.0
        assert obj["identity_kind"] == "confirmed"
        assert obj["hash_type"] == "full_sha256"
        assert obj["active_instance_count"] == 2
        assert obj["host_count"] == 1
        assert {item["path"] for item in obj["instances"]} == {"/srv/data/a.csv", "/srv/other/b.csv"}


def test_different_content_and_missing_hash_never_merge() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "identity-probe-2")
        assets = [_file("/srv/data/a.csv", sha=_h("identity-2a")),
                  _file("/srv/data/b.csv", sha=_h("identity-2b")),
                  _file("/srv/data/c.csv", sha=""), _file("/srv/data/d.csv", sha="")]
        assert _post(client, probe_id, token, _report("r-identity-2", assets)).status_code == 200

        assert client.get(f"/api/v1/data-objects?probe_id={probe_id}").json()["total"] == 4
        scoped = client.get(f"/api/v1/data-objects?probe_id={probe_id}&identity_kind=scoped").json()
        assert scoped["total"] == 2
        # A scoped object states that its identity is weak instead of implying a hash.
        for item in scoped["items"]:
            assert item["identity_confidence"] == 0.0
            assert item["content_hash"] == ""
        confirmed = client.get(f"/api/v1/data-objects?probe_id={probe_id}&identity_kind=confirmed").json()
        assert confirmed["total"] == 2


def test_partial_fingerprint_is_a_labelled_candidate_not_a_duplicate() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "identity-probe-3")
        fingerprint = {"algorithm": "block-sample-v1", "version": PARTIAL_VERSION,
                       "value": _h("identity-3")[:32], "is_full": False, "size": 99_000_000,
                       "blocks": [[0, 65536]], "stable": True}
        assets = [_file("/srv/data/big1.csv", sha="", fingerprint=fingerprint),
                  _file("/srv/data/big2.csv", sha="", fingerprint=fingerprint)]
        assert _post(client, probe_id, token, _report("r-partial", assets)).status_code == 200

        types = client.get(f"/api/v1/data-types?probe_id={probe_id}").json()
        phone = next(item for item in types["items"] if item["category"] == "phone")
        assert phone["candidate_count"] == 1
        assert phone["confirmed_duplicate_count"] == 0
        assert phone["object_count"] == 1
        # Two instances of the same partial fingerprint is a suspected copy; a
        # lone one would stay "identity pending" instead.
        assert phone["candidate_duplicate_count"] == 1
        assert phone["identity_pending_count"] == 0
        assert types["totals"]["candidate_duplicates"] == 1
        assert types["totals"]["identity_pending"] == 0

        objects = client.get(f"/api/v1/data-objects?probe_id={probe_id}").json()
        assert objects["total"] == 1
        item = objects["items"][0]
        assert item["identity_kind"] == "candidate"
        assert item["hash_type"] == "partial_fingerprint"
        assert 0 < item["identity_confidence"] < 1


def test_lone_partial_object_is_identity_pending_not_a_copy() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "lone-partial-probe", ip="10.9.9.52")
        fingerprint = {"algorithm": "block-sample-v1", "version": PARTIAL_VERSION,
                       "value": _h("lone-partial")[:32], "is_full": False, "size": 99_000_000,
                       "blocks": [[0, 65536]], "stable": True}
        asset = _file("/srv/lone/big.csv", sha="", fingerprint=fingerprint)
        assert _post(client, probe_id, token, _report("r-lone-partial", [asset])).status_code == 200
        types = client.get(f"/api/v1/data-types?probe_id={probe_id}").json()
        phone = next(item for item in types["items"] if item["category"] == "phone")
        assert phone["candidate_count"] == 1
        assert phone["candidate_duplicate_count"] == 0
        assert phone["identity_pending_count"] == 1
        assert types["totals"]["candidate_duplicates"] == 0
        assert types["totals"]["identity_pending"] == 1


def test_type_totals_deduplicate_objects_across_categories() -> None:
    """A file holding two types is one object; the rows may not be summed."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "type-totals-probe", ip="10.9.9.51")
        asset = _file("/srv/totals/both.csv", sha=_h("type-totals"),
                      categories=("phone", "email"), counts={"phone": 2, "email": 3},
                      hits=[_hit("phone"), _hit("email")])
        assert _post(client, probe_id, token, _report("r-type-totals", [asset])).status_code == 200
        body = client.get(f"/api/v1/data-types?probe_id={probe_id}").json()
        rows = {row["category"]: row for row in body["items"]}
        assert rows["phone"]["object_count"] == 1 and rows["email"]["object_count"] == 1
        totals = body["totals"]
        assert totals["objects"] == 1
        assert totals["instances"] == 1
        assert totals["types"] == 2
        assert totals["confirmed_duplicates"] == 0
        assert body["totals_scope"] == f"probe:{probe_id}"


def test_probe_scope_does_not_borrow_another_hosts_copies() -> None:
    """A full-hash object on two probes is one copy per probe, not one duplicate."""
    with TestClient(app) as client:
        probe_a, token_a = _register_probe(client, "scope-a-probe", ip="10.9.9.53")
        probe_b, token_b = _register_probe(client, "scope-b-probe", ip="10.9.9.54")
        sha = _h("scope-copies")
        assert _post(client, probe_a, token_a,
                     _report("r-scope-a", [_file("/srv/scope/a.csv", sha=sha)])).status_code == 200
        assert _post(client, probe_b, token_b,
                     _report("r-scope-b", [_file("/srv/scope/b.csv", sha=sha)])).status_code == 200
        scoped = client.get(f"/api/v1/data-types?probe_id={probe_a}").json()
        assert scoped["totals"]["instances"] == 1
        assert scoped["totals"]["confirmed_duplicates"] == 0
        phone = next(item for item in scoped["items"] if item["category"] == "phone")
        assert phone["confirmed_duplicate_count"] == 0


def test_sensitivity_override_applies_to_object_and_instance_views() -> None:
    """An operator override must reach every current view, not just the type centre."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "override-probe", ip="10.9.9.55")
        assert _post(client, probe_id, token,
                     _report("r-override", [_file("/srv/override/a.csv", sha=_h("override"))])
                     ).status_code == 200
        with SessionLocal() as db:
            db.add(SystemSetting(key="sensitivity_levels", value={"PHONE": "L4"}))
            db.commit()
        try:
            objects = client.get(f"/api/v1/data-objects?probe_id={probe_id}").json()["items"]
            assert objects and objects[0]["level"] == "L4"
            assert objects[0]["level_source"] == "settings_override"
            # The scan-time value is a different axis and is never overwritten.
            assert objects[0]["sensitivity"] == "Medium"
            instances = client.get(f"/api/v1/asset-instances?probe_id={probe_id}").json()["items"]
            assert instances[0]["level"] == "L4"
            detail = client.get(f"/api/v1/asset-instances/{instances[0]['id']}").json()
            assert detail["level"] == "L4"
            assert detail["level_source"] == "settings_override"
            types = client.get(f"/api/v1/data-types?probe_id={probe_id}").json()
            phone = next(item for item in types["items"] if item["category"] == "phone")
            assert phone["level"] == "L4" and phone["source"] == "settings_override"
        finally:
            with SessionLocal() as db:
                row = db.scalar(select(SystemSetting).where(SystemSetting.key == "sensitivity_levels"))
                if row is not None:
                    db.delete(row)
                    db.commit()


def test_sensitive_findings_list_object_model_detections_as_their_own_source() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "sensitive-findings-probe", ip="10.9.9.56")
        assert _post(client, probe_id, token,
                     _report("r-sensitive-findings", [_file("/srv/findings/a.csv",
                                                            sha=_h("sensitive-findings"))])
                     ).status_code == 200
        body = client.get("/api/v1/sensitive/findings").json()
        sources = {item["source"]: item for item in body["sources"]}
        assert sources["object_model"]["kind"] == "probe_detection"
        assert sources["object_model"]["count"] >= 1
        assert sources["data_engine"]["kind"] == "file_scan"
        assert any(item["category"] == "phone" for item in body["entities"])
        assert body["totals"]["objects"] >= 1


# --- defects found by the stage 5/6 end-to-end run --------------------------

def test_probe_fingerprint_evidence_is_consumed_verbatim_by_the_platform() -> None:
    """The platform must accept exactly what the probe's Fingerprint emits.

    The two halves were once written against different shapes, and only the
    hand-built platform fixture ever passed: the probe computed a partial digest
    and then never sent the value, so every large file fell back to a scope-local
    identity and the whole candidate path was dead. This test feeds the *real*
    ``Fingerprint`` output through the ingestion API.
    """
    from shared.scanning.fingerprint import Fingerprint

    emitted = Fingerprint(hash_type="PARTIAL_FINGERPRINT", value=_h("probe-emitted"),
                          algorithm="sha256", version=PARTIAL_VERSION, file_size=67_108_910,
                          block_size=65536, blocks=[{"position": 0, "offset": 0, "length": 65536}],
                          bytes_read=327680, stable=True).as_evidence()
    assert emitted["is_full"] is False
    emitted["partial"] = True

    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "identity-probe-emitted")
        assets = [_file("/srv/data/huge1.bin", sha="", fingerprint=emitted, categories=("phone",)),
                  _file("/srv/data/huge2.bin", sha="", fingerprint=emitted, categories=("phone",))]
        assert _post(client, probe_id, token, _report("r-emitted", assets)).status_code == 200

        objects = client.get(f"/api/v1/data-objects?probe_id={probe_id}").json()
        assert objects["total"] == 1, "two identical partial fingerprints are one candidate object"
        item = objects["items"][0]
        assert item["hash_type"] == "partial_fingerprint"
        assert item["identity_kind"] == "candidate"
        assert 0 < item["identity_confidence"] < 1

        types = client.get(f"/api/v1/data-types?probe_id={probe_id}").json()
        phone = next(row for row in types["items"] if row["category"] == "phone")
        assert phone["candidate_count"] == 1
        assert phone["confirmed_duplicate_count"] == 0


def test_a_non_digest_partial_value_never_becomes_an_object_key() -> None:
    """A redaction placeholder or a truncated paste must not merge objects."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "identity-probe-nondigest")
        bogus = {"algorithm": "sha256", "version": PARTIAL_VERSION, "value": "[redacted]",
                 "is_full": False, "size": 4096, "blocks": [], "stable": True}
        assets = [_file("/srv/data/x1.bin", sha="", fingerprint=bogus),
                  _file("/srv/data/x2.bin", sha="", fingerprint=bogus)]
        assert _post(client, probe_id, token, _report("r-nondigest", assets)).status_code == 200
        objects = client.get(f"/api/v1/data-objects?probe_id={probe_id}").json()
        assert objects["total"] == 2, "an unusable digest must stay scope-local"
        assert {item["hash_type"] for item in objects["items"]} == {"scoped"}


def test_paths_under_an_excluded_subtree_are_retired_not_frozen() -> None:
    """An excluded subtree is never reported again, so it must not stay ACTIVE.

    The probe stops collecting it; the platform therefore stops seeing it and has
    to retire it. Treating "excluded" as "unjudgeable" instead would leave the row
    ACTIVE forever, which reads as a file we still know is there.
    """
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "scope-filter-probe")
        assert _post(client, probe_id, token, _report("r-scope-1", [
            _file("/srv/data/keep/a.csv", sha=_h("scope-keep")),
            _file("/srv/data/tmp/b.csv", sha=_h("scope-tmp"))])).status_code == 200
        before = {row["path"]: row["status"] for row in
                  client.get(f"/api/v1/asset-instances?probe_id={probe_id}").json()["items"]}
        assert before["/srv/data/tmp/b.csv"] == "ACTIVE"

        # The next run is complete, excludes /srv/data/tmp, and reports only what it
        # walked - exactly the coverage block the probe now sends.
        payload = _report("r-scope-2", [_file("/srv/data/keep/a.csv", sha=_h("scope-keep"))],
                          paths=("/srv/data",))
        payload["coverage"] = {**payload["coverage"], "scope_filter": {
            "exclude_paths": ["/srv/data/tmp"], "file_types": [],
            "excluded_files": 0, "excluded_directories": 1, "files_filtered_by_type": 0}}
        assert _post(client, probe_id, token, payload).status_code == 200

        after = {row["path"]: row["status"] for row in
                 client.get(f"/api/v1/asset-instances?probe_id={probe_id}").json()["items"]}
        assert after["/srv/data/tmp/b.csv"] == "NOT_OBSERVED"
        assert after["/srv/data/keep/a.csv"] == "ACTIVE"


def test_scope_test_ignores_exclusions_by_design() -> None:
    """Pins the decision above: excludes must not remove paths from the sweep.

    A scope test that consulted the exclusions would make the platform unable to
    ever retire an excluded path, so this asserts the raw behaviour.
    """
    assert svc.in_scope("/srv/data/tmp/b.csv", ["/srv/data"], 3, "file") is True
    assert svc.in_scope("/srv/data/deep/deeper/x.csv", ["/srv/data"], 0, "file") is False
    assert svc.in_scope("/other/x.csv", ["/srv/data"], 3, "file") is False


def test_swept_instance_is_reflected_in_the_object_counters_immediately() -> None:
    """autoflush is off, so the sweep must be flushed before the counters are read."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "sweep-counter-probe")
        shared = _h("sweep-counter")
        # Two paths, identical content: one object with two active instances.
        assert _post(client, probe_id, token, _report("r-counter-1", [
            _file("/srv/data/one.csv", sha=shared), _file("/srv/data/two.csv", sha=shared)],
        )).status_code == 200
        objects = client.get(f"/api/v1/data-objects?probe_id={probe_id}").json()
        assert objects["total"] == 1
        object_id = objects["items"][0]["id"]
        assert objects["items"][0]["active_instance_count"] == 2

        # The second run sees only one of them and is complete, so the other is gone.
        assert _post(client, probe_id, token, _report("r-counter-2", [
            _file("/srv/data/one.csv", sha=shared)], paths=("/srv/data",))).status_code == 200
        detail = client.get(f"/api/v1/data-objects/{object_id}").json()
        assert detail["active_instance_count"] == 1, "the swept copy must not still count as live"
        assert detail["instance_count"] == 2

def test_same_hash_on_two_probes_shares_the_object_but_not_the_host() -> None:
    with TestClient(app) as client:
        first_id, first_token = _register_probe(client, "host-a", ip="10.0.0.1")
        second_id, second_token = _register_probe(client, "host-b", ip="10.0.0.1")
        shared = _h("host-shared")
        assert _post(client, first_id, first_token,
                     _report("r-host-a", [_file("/srv/data/x.csv", sha=shared)])).status_code == 200
        assert _post(client, second_id, second_token,
                     _report("r-host-b", [_file("/srv/data/x.csv", sha=shared)])).status_code == 200

        objects = client.get(f"/api/v1/data-objects?probe_id={first_id}").json()
        assert objects["total"] == 1
        detail = client.get(f"/api/v1/data-objects/{objects['items'][0]['id']}").json()
        # One object, two instances, and the host count is real rather than an IP merge.
        assert detail["active_instance_count"] == 2
        assert detail["host_count"] == 2
        rows = client.get("/api/v1/data-types").json()["items"]
        phone = next(item for item in rows if item["category"] == "phone")
        assert phone["host_count"] >= 2

# --- detections and evidence ------------------------------------------------
def test_returned_matched_text_travels_with_the_evidence_row() -> None:
    """The原文 a scan returned is stored on its evidence row and served back.

    An empty one must never erase text that was already returned: a later scan
    that only saw the field name cannot un-say what the first scan proved.
    """
    hits = [_hit("phone", field="mobile", sheet="Sheet1",
                 matches=[{"value": "13800138000", "context": "mobile,13800138000"}])]
    assets = [_file("/srv/data/contacts.csv", hits=hits)]
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "matched-text-probe")
        assert _post(client, probe_id, token, _report("r-match-1", assets)).status_code == 200
        instance_id = client.get(
            f"/api/v1/asset-instances?probe_id={probe_id}").json()["items"][0]["id"]
        detection_id = next(
            item["id"] for item in
            client.get(f"/api/v1/asset-instances/{instance_id}").json()["detections"]
            if item["category"] == "phone")
        covered = client.get(f"/api/v1/detections/{detection_id}/evidence").json()
        assert covered["matches_returned"] == 1
        assert covered["items"][0]["matches"] == [
            {"value": "13800138000", "context": "mobile,13800138000"}]

        # A second scan with no returned text keeps the stored sample.
        bare = [_hit("phone", field="mobile", sheet="Sheet1")]
        assert _post(client, probe_id, token, _report(
            "r-match-2", [_file("/srv/data/contacts.csv", hits=bare)],
            observed_at="2026-09-15T02:00:00+00:00")).status_code == 200
        kept = client.get(f"/api/v1/detections/{detection_id}/evidence").json()
        assert kept["items"][0]["matches"] == [
            {"value": "13800138000", "context": "mobile,13800138000"}]


def test_returned_matched_text_is_rebounded_by_the_platform() -> None:
    """A host cannot widen the caps by sending more or longer strings."""
    hits = [_hit("phone", field="mobile",
                 matches=[{"value": "1" * 400, "context": "c" * 900} for _ in range(9)])]
    assets = [_file("/srv/data/wide.csv", hits=hits)]
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "matched-text-bounds-probe")
        assert _post(client, probe_id, token, _report("r-match-3", assets)).status_code == 200
        instance_id = client.get(
            f"/api/v1/asset-instances?probe_id={probe_id}").json()["items"][0]["id"]
        detection_id = next(
            item["id"] for item in
            client.get(f"/api/v1/asset-instances/{instance_id}").json()["detections"]
            if item["category"] == "phone")
        covered = client.get(f"/api/v1/detections/{detection_id}/evidence").json()
        assert covered["matches_returned"] == 3
        for item in covered["items"][0]["matches"]:
            assert len(item["value"]) == 120
            assert len(item["context"]) == 240


def test_one_detection_per_instance_and_type_with_deduplicated_evidence() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "detection-probe")
        # Three rules and two evidence kinds agreeing on the same column must not
        # become six detections or six times the hit count.
        hits = [_hit("phone", count=4, rules=("SD_PHONE_001",),
                     evidence_types=("regex", "field_name"), field="mobile", sheet="Sheet1"),
                _hit("phone", count=4, rules=("SD_PHONE_002",),
                     evidence_types=("regex", "field_name"), field="mobile", sheet="Sheet1"),
                _hit("id_card", count=1, rules=("SD_ID_CARD_001",), evidence_types=("validator",))]
        assets = [_file("/srv/data/pii.csv", sha=_h("det-1"), categories=("phone", "id_card"),
                        counts={"phone": 4, "id_card": 1}, hits=hits)]
        assert _post(client, probe_id, token, _report("r-det-1", assets)).status_code == 200

        instances = client.get(f"/api/v1/asset-instances?probe_id={probe_id}").json()
        assert instances["total"] == 1
        instance_id = instances["items"][0]["id"]
        detail = client.get(f"/api/v1/asset-instances/{instance_id}").json()
        assert {item["category"] for item in detail["detections"]} == {"phone", "id_card"}
        assert len(detail["detections"]) == 2

        phone = next(item for item in detail["detections"] if item["category"] == "phone")
        evidence = client.get(f"/api/v1/detections/{phone['id']}/evidence").json()
        keys = {(item["rule_id"], item["evidence_type"]) for item in evidence["items"]}
        # Two rules x two kinds, but the pair (SD_PHONE_001, regex) appears once.
        assert keys == {("SD_PHONE_001", "regex"), ("SD_PHONE_001", "field_name"),
                        ("SD_PHONE_002", "regex"), ("SD_PHONE_002", "field_name")}
        assert evidence["items"][0]["field_name"] == "mobile"
        assert evidence["items"][0]["sheet_name"] == "Sheet1"
        assert "原文" in evidence["note"]
        # No returned text in this fixture: the row says so instead of pretending.
        assert evidence["items"][0]["matches"] == []
        assert evidence["matches_returned"] == 0

        # Re-sending the same scan must not duplicate evidence rows.
        assert _post(client, probe_id, token, _report("r-det-1b", assets,
                                                      observed_at="2026-09-15T01:00:00+00:00")).status_code == 200
        again = client.get(f"/api/v1/detections/{phone['id']}/evidence").json()
        assert again["count"] == evidence["count"]


def test_directory_rollup_is_not_stored_as_an_independent_detection() -> None:
    """A directory advertises its children's categories, not its own hits."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "directory-probe")
        child = _file("/srv/data/pii.csv", sha=_h("dir-child"),
                      categories=("phone",), counts={"phone": 3})
        directory = _file("/srv/data", categories=("phone",), counts={}, hits=[], size=4096)
        directory["asset_type"] = "directory"
        directory["evidence"] = {"coverage": "complete", "termination_reason": "complete",
                                 "file_count": 1, "aggregate": True}
        assert _post(client, probe_id, token, _report("r-dir-1", [child, directory])).status_code == 200

        instances = client.get(f"/api/v1/asset-instances?probe_id={probe_id}").json()
        by_path = {item["path"]: item for item in instances["items"]}
        # The roll-up label survives; the roll-up itself is not a finding.
        assert by_path["/srv/data"]["categories"] == ["phone"]
        with SessionLocal() as db:
            directory_rows = db.scalars(select(Detection).where(
                Detection.instance_id == by_path["/srv/data"]["id"])).all()
            child_rows = db.scalars(select(Detection).where(
                Detection.instance_id == by_path["/srv/data/pii.csv"]["id"])).all()
        assert directory_rows == []
        assert [row.category for row in child_rows] == ["phone"]
        assert child_rows[0].hit_count == 3
        # And the type centre counts only the file that really holds a hit.
        types = client.get(f"/api/v1/data-types?probe_id={probe_id}").json()
        phone = next(item for item in types["items"] if item["category"] == "phone")
        assert phone["object_count"] == 1
        assert phone["active_instance_count"] == 1


def test_partial_report_never_labels_a_directory_rollup_complete() -> None:
    """A roll-up has no parser coverage, so it must not borrow "complete"."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "directory-coverage-probe")
        directory = _file("/srv/dir", categories=("phone",), counts={}, hits=[])
        directory["asset_type"] = "directory"
        directory["evidence"] = {"file_count": 3}
        partial = _report("r-dir-cov-1", [directory], paths=("/srv/dir",),
                          complete=False, completed_scope=False)
        partial["coverage"] = {**partial["coverage"], "termination_reason": "row_budget"}
        assert _post(client, probe_id, token, partial).status_code == 200
        instance_id = client.get(
            f"/api/v1/asset-instances?probe_id={probe_id}").json()["items"][0]["id"]
        detail = client.get(f"/api/v1/asset-instances/{instance_id}").json()
        assert detail["coverage"] == "partial"
        assert detail["termination_reason"] == "row_budget"
        # A later walk that really finished may say so.
        assert _post(client, probe_id, token,
                     _report("r-dir-cov-2", [directory], paths=("/srv/dir",),
                             observed_at="2026-09-16T00:00:00+00:00")).status_code == 200
        assert client.get(
            f"/api/v1/asset-instances/{instance_id}").json()["coverage"] == "complete"


def test_projection_sensitivity_is_never_weaker_than_the_platform_mapping() -> None:
    """A probe whose local severity map lags must not downgrade a real category."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "severity-probe")
        stale = _file("/srv/data/stale.csv", sha=_h("sev-stale"),
                      categories=("se_organisationsnummer",),
                      counts={"se_organisationsnummer": 1},
                      hits=[_hit("se_organisationsnummer", count=1)])
        stale["sensitivity"] = "Low"
        hinted = _file("/srv/data/hinted.csv", sha=_h("sev-hinted"), categories=(),
                       counts={}, hits=[])
        hinted["sensitivity"] = "Unknown"
        assert _post(client, probe_id, token,
                     _report("r-sev-1", [stale, hinted])).status_code == 200
        with SessionLocal() as db:
            rows = {row.extra["path"]: row for row in db.scalars(
                select(DataAsset).where(
                    DataAsset.extra["probe_id"].as_integer() == probe_id)).all()}
        # The uploaded detection says Medium, so the list row may not say Low.
        assert rows["/srv/data/stale.csv"].sensitivity == "Medium"
        # A candidate/port entry has no category to map, so its own word is kept.
        assert rows["/srv/data/hinted.csv"].sensitivity == "Unknown"


def test_detection_never_carries_a_matched_value() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "detection-probe-2")
        assets = [_file("/srv/data/pii2.csv", sha=_h("det-2"), hits=[_hit("phone", count=1)])]
        assert _post(client, probe_id, token, _report("r-det-2", assets)).status_code == 200
    with SessionLocal() as db:
        for row in db.scalars(select(DetectionEvidence)).all():
            assert not any(isinstance(value, str) and value.isdigit() and len(value) == 11
                           for value in (row.rule_id, row.rule_name, row.field_name, row.sheet_name))
        # The whole stored vocabulary is structural: no value-shaped column exists.
        assert not hasattr(DetectionEvidence, "matched_value")
        assert not hasattr(Detection, "sample_values")


# --- scope-aware lifecycle --------------------------------------------------
def _instance_statuses(probe_id: int) -> dict[str, str]:
    with SessionLocal() as db:
        rows = db.scalars(select(AssetInstance).where(AssetInstance.probe_id == probe_id)).all()
        return {row.path: row.status for row in rows}


def test_complete_scope_marks_unseen_instances_not_observed() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "scope-probe")
        assets = [_file("/srv/data/keep.csv", sha=_h("scope-keep")),
                  _file("/srv/data/gone.csv", sha=_h("scope-gone"))]
        assert _post(client, probe_id, token, _report("r-scope-1", assets)).status_code == 200
        assert _instance_statuses(probe_id) == {"/srv/data/keep.csv": "ACTIVE",
                                                "/srv/data/gone.csv": "ACTIVE"}

        second = _report("r-scope-2", [_file("/srv/data/keep.csv", sha=_h("scope-keep"))],
                         observed_at="2026-09-16T00:00:00+00:00")
        result = _post(client, probe_id, token, second).json()
        assert result["complete_scope"] is True
        assert result["not_observed"] == 1
        assert _instance_statuses(probe_id) == {"/srv/data/keep.csv": "ACTIVE",
                                                "/srv/data/gone.csv": "NOT_OBSERVED"}

        # The legacy projection follows, so an old page keeps its existing meaning.
        listed = client.get(f"/api/v1/data/assets?probe_id={probe_id}").json()
        by_path = {item["path"]: item for item in listed["items"]}
        assert by_path["/srv/data/gone.csv"]["status"] == "not_observed"
        assert by_path["/srv/data/keep.csv"]["status"] == "observed"


def test_incomplete_scope_never_declares_data_gone() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "scope-probe-2")
        assets = [_file("/srv/data/x.csv", sha=_h("scope2-x")),
                  _file("/srv/data/y.csv", sha=_h("scope2-y"))]
        assert _post(client, probe_id, token, _report("r-scope2-1", assets)).status_code == 200

        # A timeout: the walk stopped early, so nothing may be called missing.
        partial = _report("r-scope2-2", [], complete=False, completed_scope=False,
                          observed_at="2026-09-16T00:00:00+00:00",
                          error="budget: timeout 120s", reason_code="TIMEOUT",
                          termination_reason="timeout")
        result = _post(client, probe_id, token, partial).json()
        assert result["complete_scope"] is False
        assert result["not_observed"] == 0
        assert _instance_statuses(probe_id) == {"/srv/data/x.csv": "ACTIVE",
                                                "/srv/data/y.csv": "ACTIVE"}


def test_instance_outside_the_scanned_depth_is_left_alone() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "scope-probe-3")
        assert _post(client, probe_id, token,
                     _report("r-scope3-1", [_file("/srv/data/a/b/c/deep.csv", sha=_h("scope3"))],
                             paths=("/srv/data",))).status_code == 200
        # The entry itself was inside the old scope, so it is swept...
        assert _post(client, probe_id, token,
                     _report("r-scope3-2", [], paths=("/srv/data",),
                             observed_at="2026-09-16T00:00:00+00:00")).json()["not_observed"] == 1
        # ...but a file the new scope could never have visited keeps its status.
        assert _post(client, probe_id, token,
                     _report("r-scope3-3", [_file("/srv/data/a/b/c/deep.csv", sha=_h("scope3"))],
                             paths=("/srv/other",), observed_at="2026-09-17T00:00:00+00:00")) \
            .json()["not_observed"] == 0
        assert _instance_statuses(probe_id)["/srv/data/a/b/c/deep.csv"] == "ACTIVE"


def test_renaming_creates_a_new_instance_and_the_old_one_is_not_repointed() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "rename-probe")
        digest = _h("rename")
        assert _post(client, probe_id, token,
                     _report("r-rename-1", [_file("/srv/data/old.csv", sha=digest)])).status_code == 200
        assert _post(client, probe_id, token,
                     _report("r-rename-2", [_file("/srv/data/new.csv", sha=digest)],
                             observed_at="2026-09-16T00:00:00+00:00")).status_code == 200

        with SessionLocal() as db:
            rows = {row.path: row for row in db.scalars(select(AssetInstance).where(
                AssetInstance.probe_id == probe_id)).all()}
        assert set(rows) == {"/srv/data/old.csv", "/srv/data/new.csv"}
        assert rows["/srv/data/old.csv"].status == "NOT_OBSERVED"
        # Both paths still point at the same object: a rename is a new instance,
        # not a new identity.
        assert rows["/srv/data/old.csv"].object_id == rows["/srv/data/new.csv"].object_id


def test_content_change_keeps_the_old_objects_detections_as_history() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "content-probe")
        path = "/srv/data/evolving.csv"
        assert _post(client, probe_id, token,
                     _report("r-content-1", [_file(path, sha=_h("content-v1"),
                                                   categories=("phone",),
                                                   hits=[_hit("phone", count=3)])])).status_code == 200
        with SessionLocal() as db:
            first = db.scalar(select(AssetInstance).where(AssetInstance.probe_id == probe_id))
            first_object = first.object_id

        assert _post(client, probe_id, token,
                     _report("r-content-2", [_file(path, sha=_h("content-v2"),
                                                   categories=("id_card",),
                                                   counts={"id_card": 1},
                                                   hits=[_hit("id_card", count=1)])],
                             observed_at="2026-09-16T00:00:00+00:00")).status_code == 200
        instance_id = client.get(f"/api/v1/asset-instances?probe_id={probe_id}").json()["items"][0]["id"]
        detail = client.get(f"/api/v1/asset-instances/{instance_id}").json()
        assert detail["object_id"] != first_object
        assert [item["category"] for item in detail["detections"]] == ["id_card"]

        history = client.get(f"/api/v1/asset-instances/{detail['id']}?include_history=true").json()
        assert {item["category"] for item in history["detections"]} == {"phone", "id_card"}
        # The previous object still exists with its own evidence.
        old = client.get(f"/api/v1/data-objects/{first_object}").json()
        assert old["categories"] == ["phone"]
        assert client.get(f"/api/v1/data-objects/{first_object}/detections").json()["total"] == 1


def test_late_report_cannot_roll_back_a_newer_scan() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "late-probe")
        path = "/srv/data/late.csv"
        assert _post(client, probe_id, token,
                     _report("r-late-1", [_file(path, sha=_h("late-v1"))],
                             observed_at="2026-09-15T00:00:00+00:00")).status_code == 200
        assert _post(client, probe_id, token,
                     _report("r-late-2", [_file(path, sha=_h("late-v2"))],
                             observed_at="2026-09-16T00:00:00+00:00")).status_code == 200
        with SessionLocal() as db:
            instance = db.scalar(select(AssetInstance).where(AssetInstance.probe_id == probe_id))
            current_object, seen_at = instance.object_id, instance.last_seen_at

        result = _post(client, probe_id, token,
                       _report("r-late-3", [_file(path, sha=_h("late-v1"))],
                               observed_at="2026-09-15T12:00:00+00:00")).json()
        assert result["assets"] == 0 and result["stale"] == 1
        with SessionLocal() as db:
            instance = db.scalar(select(AssetInstance).where(AssetInstance.probe_id == probe_id))
            assert instance.object_id == current_object
            assert instance.last_seen_at == seen_at
            assert instance.extra["stale_reports_ignored"] == 1


def test_completed_scan_revokes_the_old_sensitive_label() -> None:
    """A file that becomes clean must stop being reported as sensitive."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "revoke-probe")
        path = "/srv/data/becomes-clean.csv"
        assert _post(client, probe_id, token,
                     _report("r-revoke-1", [_file(path, sha=_h("revoke-v1"),
                                                  counts={"phone": 3},
                                                  hits=[_hit("phone", count=3)])])).status_code == 200
        assert _post(client, probe_id, token,
                     _report("r-revoke-2", [_file(path, sha=_h("revoke-v2"), categories=(),
                                                  counts={}, hits=[])],
                             observed_at="2026-09-16T00:00:00+00:00")).status_code == 200
        instance_id = client.get(f"/api/v1/asset-instances?probe_id={probe_id}").json()["items"][0]["id"]
        detail = client.get(f"/api/v1/asset-instances/{instance_id}").json()
        assert detail["categories"] == []
        assert detail["sensitivity"] == "Low"
        # The old label stays explainable instead of disappearing silently.
        assert "phone" in detail["extra"]["category_history"]
        # The type centre no longer counts this probe's current content as phone.
        assert client.get(f"/api/v1/data-types/phone?probe_id={probe_id}").status_code == 404


def test_late_complete_report_cannot_retire_the_live_instance() -> None:
    """Out-of-order delivery is normal; the newer observation stays authoritative."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "late-sweep-probe")
        path = "/srv/data/late-sweep.csv"
        assert _post(client, probe_id, token,
                     _report("r-late-sweep-1", [_file(path, sha=_h("late-sweep-v1"))],
                             observed_at="2026-09-15T00:00:00+00:00")).status_code == 200
        # An older, complete report that observed nothing must not sweep it away.
        late = _post(client, probe_id, token,
                     _report("r-late-sweep-0", [],
                             observed_at="2026-09-14T00:00:00+00:00")).json()
        assert late["not_observed"] == 0
        with SessionLocal() as db:
            instance = db.scalar(select(AssetInstance).where(AssetInstance.probe_id == probe_id))
            assert instance.status == "ACTIVE"


def test_migrated_object_counters_are_recounted_immediately() -> None:
    """A content change must drop the old object's live copy count at once."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "migrate-probe")
        path = "/srv/data/migrate.csv"
        assert _post(client, probe_id, token,
                     _report("r-migrate-1", [_file(path, sha=_h("migrate-v1"))])).status_code == 200
        with SessionLocal() as db:
            old_object_id = db.scalar(select(AssetInstance.object_id).where(
                AssetInstance.probe_id == probe_id))
        assert _post(client, probe_id, token,
                     _report("r-migrate-2", [_file(path, sha=_h("migrate-v2"),
                                                   hits=[_hit("id_card", count=1)],
                                                   categories=("id_card",),
                                                   counts={"id_card": 1})],
                             observed_at="2026-09-16T00:00:00+00:00")).status_code == 200
        with SessionLocal() as db:
            old = db.get(DataObject, old_object_id)
            assert old is not None
            assert old.instance_count == 0
            assert old.active_instance_count == 0


def test_categories_keep_their_own_confidence_and_sample_size() -> None:
    """One file can hold a verified category and a clue that is only a clue.

    The two must not share a number: copying the file's maximum onto both made a
    keyword-only clue look as proven as an email. And a clue stays a clue -- a
    category these rules would not confirm is reported as a candidate instead of
    becoming a finding.
    """
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "confidence-probe")
        path = "/srv/data/mixed.csv"
        email = _hit("email", count=4, rules=("SD_EMAIL_001",))
        email["confidence"] = 0.85
        for item in email["evidence"]:
            item["confidence"] = 0.85
        credential = _hit("credential", count=1, rules=("SD_CREDENTIAL_001",),
                          evidence_types=("keyword",))
        credential["confidence"] = 0.3
        for item in credential["evidence"]:
            item["confidence"] = 0.3
        asset = _file(path, sha=_h("mixed-v1"), categories=("email", "credential"),
                      counts={"email": 4, "credential": 1}, hits=[email, credential])
        asset["evidence"]["rows_read"] = 2
        asset["evidence"]["sample_rows"] = 50
        assert _post(client, probe_id, token, _report("r-mixed-1", [asset])).status_code == 200
        with SessionLocal() as db:
            instance = db.scalar(select(AssetInstance).where(AssetInstance.probe_id == probe_id))
            rows = {row.category: row for row in db.scalars(
                select(Detection).where(Detection.instance_id == instance.id)).all()}
        assert round(rows["email"].confidence, 3) == 0.85
        # A ``password`` *keyword* says the file is worth checking, not that a
        # password was found in it: no finding, but the file still says so.
        assert "credential" not in rows
        listed = client.get(f"/api/v1/data/assets?probe_id={probe_id}").json()["items"]
        mixed = next(item for item in listed if item["path"] == path)
        assert mixed["categories"] == ["email"]
        assert mixed["candidate_categories"] == ["credential"]
        # The actual sample (2 rows) and the configured ceiling (50) stay apart.
        assert rows["email"].sample_size == 2 and rows["email"].sample_limit == 50
        # A later, smaller observation is current; the larger one stays as history.
        smaller = _file(path, sha=_h("mixed-v1"), categories=("email",),
                        counts={"email": 2}, hits=[email])
        assert _post(client, probe_id, token,
                     _report("r-mixed-2", [smaller],
                             observed_at="2026-09-16T00:00:00+00:00")).status_code == 200
        with SessionLocal() as db:
            current = db.scalar(select(Detection).where(
                Detection.category == "email", Detection.probe_id == probe_id))
            assert current.hit_count == 2
            assert current.sample_hit_count == 2
            assert current.extra["hit_count_history"] == 4


def test_projection_rebuild_keeps_the_reported_column_structure() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "rebuild-columns-probe")
        path = "/srv/rebuild/columns.csv"
        asset = _file(path, sha=_h("rebuild-columns"))
        asset["columns"] = [{"name": "mobile", "detected_type": "phone",
                             "sensitivity": "Medium", "confidence": 0.9,
                             "categories": ["phone"], "count": 2}]
        assert _post(client, probe_id, token, _report("r-rebuild-columns", [asset])).status_code == 200
    scoped = select(DataAsset).where(DataAsset.asset_type == "table",
                                     DataAsset.extra["probe_id"].as_integer() == probe_id,
                                     DataAsset.extra["path"].as_string() == path)
    with SessionLocal() as db:
        row = db.scalar(scoped)
        assert row is not None
        row.extra = {**row.extra, "status": "not_observed"}
        db.commit()
        svc.rebuild_projection(db, probe_id)
        db.commit()
        restored = db.scalar(scoped)
        assert [column["name"] for column in restored.columns] == ["mobile"]
        # The sensitive category is not a field name and must never be used as one.
        assert all(column["name"] != "phone" for column in restored.columns)
        assert restored.extra["evidence"]["extension"] == ".csv"
        assert restored.extra["detections"][0]["category"] == "phone"
        assert restored.extra["rebuild"]["structure_restored"] is True


def test_rebuild_labels_columns_that_were_faked_from_categories() -> None:
    """A pre-fix rebuild wrote categories into ``columns``; say so, don't hide it."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "faked-columns-probe", ip="10.9.9.57")
        path = "/srv/rebuild/faked.csv"
        assert _post(client, probe_id, token,
                     _report("r-faked-columns", [_file(path, sha=_h("faked-columns"))])
                     ).status_code == 200
    scoped = select(DataAsset).where(DataAsset.asset_type == "table",
                                     DataAsset.extra["probe_id"].as_integer() == probe_id,
                                     DataAsset.extra["path"].as_string() == path)
    with SessionLocal() as db:
        row = db.scalar(scoped)
        assert row is not None
        # Reproduce the historical damage: names are categories, real ones gone,
        # and the instance snapshot is absent so nothing can restore them.
        row.columns = [{"name": "phone"}, {"name": "id_card"}]
        row.extra = {**row.extra, "columns": [], "evidence": {}}
        instance = db.scalar(select(AssetInstance).where(
            AssetInstance.probe_id == probe_id, AssetInstance.path == path))
        instance.extra = {**(instance.extra or {}), "columns": [], "evidence": {}}
        db.commit()
        svc.rebuild_projection(db, probe_id)
        db.commit()
        restored = db.scalar(scoped)
        assert restored.extra["rebuild"]["fabricated_columns"] is True
        assert restored.extra["rebuild"]["structure_restored"] is False
        # The row keeps its values - nothing is deleted or silently renamed.
        assert [column["name"] for column in restored.columns] == ["phone", "id_card"]

# --- legacy protocol compatibility ------------------------------------------
def test_legacy_331_report_still_ingests_and_keeps_working() -> None:
    """A 3.3.1 probe sends no schema, no scan_id and no coverage block."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "legacy-probe")
        payload = {
            "report_id": "legacy-report-1",
            "assets": [{"name": "legacy.csv", "asset_type": "table", "sensitivity": "High",
                        "path": "/srv/legacy/legacy.csv", "size": 10, "sha256": _h("legacy"),
                        "modified_at": "", "categories": ["phone"],
                        "counts": {"phone": 2}, "columns": [], "evidence": {}}],
            "databases": [], "scanned_paths": ["/srv/legacy"], "complete": True,
            "observed_at": "2026-09-15T00:00:00+00:00", "scanner": "probe-file-inventory",
        }
        response = _post(client, probe_id, token, payload)
        assert response.status_code == 200
        body = response.json()
        assert body["assets"] == 1
        # Without `completed_scope`, `complete` keeps exactly the meaning it had.
        assert body["complete_scope"] is True
        assert body["scan_id"] == "legacy-report-1"
        # The detail is thinner, and the API says so instead of inventing evidence.
        detection = client.get(f"/api/v1/asset-instances?probe_id={probe_id}").json()["items"][0]
        detail = client.get(f"/api/v1/asset-instances/{detection['id']}").json()
        assert [item["category"] for item in detail["detections"]] == ["phone"]
        evidence = client.get(f"/api/v1/detections/{detail['detections'][0]['id']}/evidence").json()
        assert evidence["count"] == 0


def test_legacy_report_with_an_error_still_never_sweeps() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "legacy-probe-2")
        assert _post(client, probe_id, token,
                     _report("r-legacy2-1", [_file("/srv/legacy2/a.csv", sha=_h("legacy2"))],
                             schema="1.0")).status_code == 200
        payload = {"report_id": "r-legacy2-2", "assets": [], "databases": [],
                   "scanned_paths": ["/srv/legacy2"], "complete": True,
                   "error": "boom", "observed_at": "2026-09-16T00:00:00+00:00"}
        body = _post(client, probe_id, token, payload).json()
        assert body["complete_scope"] is False
        assert _instance_statuses(probe_id)["/srv/legacy2/a.csv"] == "ACTIVE"


def test_legacy_report_without_a_complete_flag_still_sweeps() -> None:
    """The 3.3.1 schema defaults ``complete`` to true; an omitted field means
    "the walk finished". Requiring the flag would leave a really-deleted file
    ``observed`` forever - the one outcome this model must never produce."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "legacy-probe-3")
        assert _post(client, probe_id, token,
                     _report("r-legacy3-1", [_file("/srv/legacy3/a.csv", sha=_h("legacy3"))],
                             schema="1.0")).status_code == 200
        payload = {"report_id": "r-legacy3-2", "assets": [], "databases": [],
                   "scanned_paths": ["/srv/legacy3"], "max_depth": 3,
                   "observed_at": "2026-09-16T00:00:00+00:00"}
        assert "complete" not in payload
        body = _post(client, probe_id, token, payload).json()
        assert body["complete_scope"] is True
        assert _instance_statuses(probe_id)["/srv/legacy3/a.csv"] == "NOT_OBSERVED"


def test_unknown_report_schema_is_treated_as_the_legacy_shape() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "schema-probe")
        body = _post(client, probe_id, token, _report("r-schema", [], schema="9.9")).json()
        assert body["assets"] == 0
        with SessionLocal() as db:
            task = db.get(Task, body["id"])
            assert task.result["schema_version"] == "1.0"


# --- projection, backfill and progress --------------------------------------
def test_projection_can_be_rebuilt_from_the_object_model() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "rebuild-probe")
        assert _post(client, probe_id, token,
                     _report("r-rebuild", [_file("/srv/rebuild/a.csv", sha=_h("rebuild"))])).status_code == 200
    # The session-wide database keeps rows from other tests, so the projection is
    # always addressed by (probe, path) rather than by name.
    scoped = select(DataAsset).where(DataAsset.asset_type == "table",
                                     DataAsset.extra["probe_id"].as_integer() == probe_id,
                                     DataAsset.extra["path"].as_string() == "/srv/rebuild/a.csv")
    with SessionLocal() as db:
        row = db.scalar(scoped)
        assert row is not None
        row.extra = {**row.extra, "status": "not_observed"}  # simulate divergence
        db.commit()
        result = svc.rebuild_projection(db, probe_id)
        db.commit()
        assert result["rebuilt"] >= 1
        restored = db.scalar(scoped)
        assert restored.extra["status"] == "observed"
        assert restored.asset_type == "table"
    with TestClient(app) as client:
        response = client.post("/api/v1/admin/data-assets/rebuild-projection", json={"probe_id": probe_id})
        assert response.status_code == 200
        assert response.json()["rebuilt"] >= 1


def test_backfill_projects_legacy_rows_without_inventing_metadata() -> None:
    with SessionLocal() as db:
        probe = Probe(name="backfill-probe", hostname="backfill-probe", ip_address="10.1.1.1")
        db.add(probe)
        db.flush()
        db.add(DataAsset(name="orphan.csv", asset_type="table", sensitivity="Unknown",
                         source="probe:backfill-probe", columns=[],
                         extra={"path": "/srv/backfill/orphan.csv"}))
        db.add(DataAsset(name="known.csv", asset_type="table", sensitivity="Medium",
                         source="probe:backfill-probe", columns=[],
                         extra={"probe_id": probe.id, "path": "/srv/backfill/known.csv",
                                "observed_at": "2026-09-10T00:00:00+00:00"}))
        db.commit()
        result = svc.backfill_legacy(db)
        db.commit()
        instances = {row.path: row for row in db.scalars(select(AssetInstance).where(
            AssetInstance.probe_id == probe.id)).all()}
        # A row that cannot be tied to a probe stays legacy-only rather than guessed.
        assert "/srv/backfill/orphan.csv" not in instances
        assert result["skipped"] >= 1
        backfilled = instances["/srv/backfill/known.csv"]
        assert backfilled.hash_type == svc.HASH_SCOPED
        assert backfilled.content_hash == ""
        assert backfilled.extra["metadata"] == "unknown"
        assert backfilled.last_scan_at is None
        obj = db.get(DataObject, backfilled.object_id)
        assert obj.identity_confidence == 0.0
        assert db.scalars(select(Detection).where(Detection.instance_id == backfilled.id)).all() == []


def test_progress_updates_the_task_without_touching_its_status() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "progress-probe")
        job = client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs",
                          json={"paths": ["/srv/data"], "max_files": 10}).json()
        task_id = job["id"]

        pushed = client.post(f"/api/v1/probes/{probe_id}/data-assets/progress",
                             json={"task_id": task_id, "scan_id": "scan-1",
                                   "current_path": "/srv/data/big.csv",
                                   "coverage": {"max_files": 10, "files_analyzed": 5,
                                                "files_discovered": 9, "directories_scanned": 2,
                                                "bytes_read": 4096, "sensitive_assets": 1,
                                                "detections": 3, "elapsed_seconds": 4.5}},
                             headers=_headers(probe_id, token))
        assert pushed.status_code == 200 and pushed.json()["applied"] is True
        with SessionLocal() as db:
            task = db.get(Task, task_id)
            assert task.status == "Pending"          # progress never advances the state
            assert task.progress == 50
            assert task.payload["progress"]["estimated"] is True
            assert task.payload["progress"]["basis"] == "files_analyzed/max_files"
            assert "已分析文件 5" in task.current_stage

        # A finished task ignores late progress instead of being resurrected.
        with SessionLocal() as db:
            task = db.get(Task, task_id)
            task.status = "Success"
            db.commit()
        again = client.post(f"/api/v1/probes/{probe_id}/data-assets/progress",
                           json={"task_id": task_id, "coverage": {"max_files": 10, "files_analyzed": 9}},
                           headers=_headers(probe_id, token))
        assert again.json()["applied"] is False


def test_progress_is_rejected_for_another_probe_or_an_unknown_task() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "progress-probe-2")
        other_id, other_token = _register_probe(client, "progress-probe-3")
        job = client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs",
                          json={"paths": ["/srv/data"]}).json()
        cross = client.post(f"/api/v1/probes/{other_id}/data-assets/progress",
                            json={"task_id": job["id"], "coverage": {}},
                            headers=_headers(other_id, other_token))
        assert cross.status_code == 404
        missing = client.post(f"/api/v1/probes/{probe_id}/data-assets/progress",
                              json={"task_id": 999_999, "coverage": {}},
                              headers=_headers(probe_id, token))
        assert missing.status_code == 404


# --- list APIs --------------------------------------------------------------
def test_lists_reject_an_unsupported_sort_and_paginate() -> None:
    with TestClient(app) as client:
        assert client.get("/api/v1/data-objects?order_by=object_key;drop").status_code == 400
        assert client.get("/api/v1/asset-instances?order_by=secret").status_code == 400
        listed = client.get("/api/v1/asset-instances?order_by=-size&page=1&page_size=1").json()
        assert listed["page_size"] == 1 and len(listed["items"]) <= 1
        assert client.get("/api/v1/data-types/does-not-exist").status_code == 404
        assert client.get("/api/v1/data-objects/99999999").status_code == 404
        assert client.get("/api/v1/asset-instances/99999999").status_code == 404
        assert client.get("/api/v1/detections/99999999/evidence").status_code == 404


def test_level_mapping_is_explainable_and_never_overwrites_the_legacy_field() -> None:
    with TestClient(app) as client:
        levels = client.get("/api/v1/sensitivity-levels").json()
        mapping = {item["entity"]: item for item in levels["items"]}
        assert mapping["ID_CARD"]["level"] == "L3"
        assert mapping["ID_CARD"]["severity"] == "High"
        assert mapping["API_KEY"]["level"] == "L4"
        assert mapping["PHONE"]["level"] == "L2"
        structural = {item["entity"]: item for item in levels["non_protected"]}
        assert structural["IP_ADDRESS"]["protected"] is False
        assert mapping["NAME"]["field_only"] is True
        assert mapping["ID_CARD"]["source"] == "builtin_default"
        assert set(levels["levels"]) == {"L1", "L2", "L3", "L4"}
        assert "L4" in levels["levels"]["L4"]["name"] or levels["levels"]["L4"]["name"]


# --- probe removal ----------------------------------------------------------
def test_deleting_a_probe_preserves_observations_and_evidence() -> None:
    """`DELETE /probes/{id}` keeps collected records; the object model follows.

    An instance identity is ``(probe_id, path)``, so the probe's instances,
    detections and evidence go with it - otherwise the deletion would either
    fail on the foreign key or leave a row claiming a host that no longer
    exists. The logical object and the legacy projection row stay.
    """
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "remove-probe", ip="10.7.7.7")
        assert _post(client, probe_id, token,
                     _report("r-remove", [_file("/srv/remove/a.csv", sha=_h("remove"))])).status_code == 200
        with SessionLocal() as db:
            object_id = db.scalar(select(AssetInstance.object_id).where(
                AssetInstance.probe_id == probe_id))
            assert object_id is not None
        # Registered after the victim on purpose: SQLite hands the highest
        # rowid to the next INSERT, so deleting the newest probe would let a
        # later, unrelated probe inherit this probe's task history in the
        # session-wide test database. PostgreSQL sequences never reuse ids.
        _register_probe(client, "remove-probe-tail", ip="10.7.7.8")
        removed = client.delete(f"/api/v1/probes/{probe_id}")
        assert removed.status_code == 200, removed.text
    with SessionLocal() as db:
        assert db.scalars(select(AssetInstance).where(
            AssetInstance.probe_id == probe_id)).all() == []
        assert db.scalars(select(Detection).where(Detection.probe_id == probe_id)).all() == []
        obj = db.get(DataObject, object_id)
        assert obj is not None, "the logical object outlives the probe that first saw it"
        assert obj.instance_count == 1 and obj.active_instance_count == 0
        archived = db.scalar(select(AssetInstance).where(AssetInstance.object_id == object_id))
        assert archived.status == 'SOURCE_RETIRED'
        assert archived.owner_key == f'probe:{probe_id}'
        detections = list(db.scalars(select(Detection).where(Detection.instance_id == archived.id)))
        assert detections
        assert db.scalar(select(DetectionEvidence).where(DetectionEvidence.detection_id == detections[0].id)) is not None
        assert db.scalars(select(DataAsset).where(
            DataAsset.extra["probe_id"].as_integer() == probe_id)).all() != []


def test_task_asset_membership_survives_rescan_and_isolates_probes() -> None:
    with TestClient(app) as client:
        pid, token = _register_probe(client, "task-membership")
        other, other_token = _register_probe(client, "task-membership-other")
        first = _post(client, pid, token, _report("membership-1", [
            _file("/srv/data/member.csv", sha=_h("member")),
            _file("/srv/data/clean.csv", sha=_h("clean-member"), categories=(), hits=[]),
        ])).json()
        _post(client, other, other_token, _report("membership-1", [
            _file("/srv/data/other.csv", sha=_h("other-member"))]))
        _post(client, pid, token, _report("membership-2", [
            _file("/srv/data/member.csv", sha=_h("member-updated")),
        ], observed_at="2026-09-16T00:00:00+00:00"))
        response = client.get('/api/v1/asset-instances', params={'task_id': first['id'], 'page_size': 1})
        assert response.status_code == 200
        body = response.json()
        assert body['total'] == 2
        assert len(body['items']) == 1
        assert body['association'] == 'recorded_membership'
        assert body['items'][0]['probe_id'] == pid
        # Older tasks have only last_scan_id: expose that limitation explicitly.
        with SessionLocal() as db:
            task = db.get(Task, first['id'])
            task.result = {k: v for k, v in task.result.items() if k != 'asset_instance_ids'}
            db.commit()
        legacy = client.get('/api/v1/asset-instances', params={'task_id': first['id']}).json()
        assert legacy['association'] == 'latest_scan_only'
        assert legacy['total'] == 1
        assert legacy['items'][0]['name'] == 'clean.csv'
        assert client.get('/api/v1/asset-instances?task_id=99999999').status_code == 404
