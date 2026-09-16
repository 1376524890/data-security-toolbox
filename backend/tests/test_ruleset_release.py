"""Central rule sets: immutable publications, real validation, traceable rollback.

The published bytes *are* the artifact a probe downloads, so a test that only
compares re-serialised rules would miss the failure that matters: a version whose
stored bytes no longer match the digest advertised in its manifest.
"""
from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app
from app.models import Rule, RuleSet, RuleSetVersion
from app.services import ruleset_service
from app.services.ruleset_service import RuleSetError

BASELINE = ruleset_service.BASELINE_VERSION


def _rule(rule_id: str = "TEST_RULE_1", **overrides) -> dict:
    rule = {
        "rule_id": rule_id,
        "name": "测试手机号",
        "entity": "PHONE",
        "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)",
        "confidence": 0.7,
        "validator": "cn_mobile",
        "enabled": True,
        "rule_source": "manual",
    }
    rule.update(overrides)
    return rule


@pytest.fixture()
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# --- publication -----------------------------------------------------------

def test_baseline_is_published_once_with_the_builtin_rules(db) -> None:
    rule_set = ruleset_service.ensure_baseline(db)
    first = ruleset_service.active_version(db, rule_set)
    assert first is not None and first.version == BASELINE
    assert first.rule_count > 0
    assert first.sha256 == hashlib.sha256(first.package).hexdigest()

    # Idempotent: a second boot must not publish a second baseline.
    again = ruleset_service.ensure_baseline(db)
    assert ruleset_service.active_version(db, again).id == first.id
    versions = db.scalars(select(RuleSetVersion).where(RuleSetVersion.rule_set_id == rule_set.id)).all()
    assert [row.version for row in versions].count(BASELINE) == 1


def test_publishing_the_same_version_twice_is_refused(db) -> None:
    rule_set = ruleset_service.ensure_baseline(db)
    ruleset_service.publish(db, rule_set, version="rel-1", published_by="tester")
    with pytest.raises(RuleSetError, match="已存在"):
        ruleset_service.publish(db, rule_set, version="rel-1", published_by="tester")


def test_editing_the_working_copy_does_not_change_a_published_version(db) -> None:
    rule_set = ruleset_service.ensure_baseline(db)
    row = ruleset_service.publish(db, rule_set, version="rel-1", published_by="tester")
    stored = row.package
    digest = row.sha256

    target = db.scalar(select(Rule).where(Rule.rule_set_id == rule_set.id, Rule.rule_id == "TEST_RULE_1"))
    if target is None:
        target = Rule(rule_set_id=rule_set.id, rule_id="TEST_RULE_1", entity="PHONE", pattern=r"1[3-9]\d{9}")
        db.add(target)
    target.pattern = r"1[3-9]\d{9}"
    target.name = "改过的名字"
    db.flush()

    db.refresh(row)
    assert row.package == stored
    assert row.sha256 == digest
    # And the manifest still advertises the digest of those exact bytes.
    assert ruleset_service.version_manifest(db, row)["sha256"] == hashlib.sha256(stored).hexdigest()


def test_manifest_reports_the_real_size_and_version(db) -> None:
    rule_set = ruleset_service.ensure_baseline(db)
    row = ruleset_service.publish(db, rule_set, version="rel-2", published_by="tester")
    manifest = ruleset_service.version_manifest(db, row)
    assert manifest["size"] == len(row.package)
    assert manifest["ruleset_version"] == "rel-2"
    assert manifest["rule_count"] == row.rule_count
    assert manifest["engine_version"]
    assert manifest["schema_version"]


def test_publishing_supersedes_the_previous_version_without_deleting_it(db) -> None:
    rule_set = ruleset_service.ensure_baseline(db)
    first = ruleset_service.active_version(db, rule_set)
    second = ruleset_service.publish(db, rule_set, version="rel-3", published_by="tester")
    db.refresh(first)
    assert first.status == "superseded"
    assert second.status == "published"
    assert db.get(RuleSetVersion, first.id) is not None


def test_capabilities_describe_the_negotiable_contract() -> None:
    caps = ruleset_service.capabilities()
    assert caps["rulesets"] is True
    assert caps["digest"] == "sha256"
    assert caps["max_pack_bytes"] > 0
    assert caps["schema_version"] and caps["engine_version"]


# --- validation ------------------------------------------------------------

@pytest.mark.parametrize(
    "version, rules, message",
    [
        ("bad version!", [_rule()], "版本号"),
        ("rel-9", [], "不能为空"),
        ("rel-9", [_rule(), _rule()], "重复"),
        ("rel-9", [_rule(pattern=".*")], "校验失败"),
        ("rel-9", [_rule(validator="not_a_validator")], "校验失败"),
        ("rel-9", [_rule(enabled=False)], "至少"),
    ],
)
def test_unusable_publications_are_refused_with_a_reason(version: str, rules: list[dict], message: str) -> None:
    with pytest.raises(RuleSetError, match=message):
        ruleset_service.build_pack(rules, version)


def test_a_pack_larger_than_the_probe_limit_is_refused() -> None:
    rules = [_rule(f"BIG_{index}", pattern=rf"(?<!\d)9{index}\d{{8}}(?!\d)", description="x" * 2000)
             for index in range(ruleset_service.MAX_RULES_PER_PACK + 1)]
    with pytest.raises(RuleSetError, match="超过上限"):
        ruleset_service.build_pack(rules, "rel-big")


def test_pack_bytes_are_stable_and_self_consistent() -> None:
    stamp = "2026-09-16T00:00:00+00:00"
    payload, prepared = ruleset_service.build_pack([_rule()], "rel-stable", created_at=stamp)
    document = json.loads(payload.decode("utf-8"))
    assert document["ruleset_version"] == "rel-stable"
    assert document["created_at"] == stamp
    assert len(prepared) == 1
    # With the timestamp pinned the bytes are reproducible, so a digest comparison
    # across releases is meaningful. Without it the pack would look different on
    # every publish even when nothing changed.
    assert ruleset_service.build_pack([_rule()], "rel-stable", created_at=stamp)[0] == payload


def test_the_pack_never_carries_a_matched_value() -> None:
    payload, _ = ruleset_service.build_pack([_rule()], "rel-pii")
    text = payload.decode("utf-8")
    assert "13800138000" not in text
    assert "110101199003076173" not in text


# --- rollback --------------------------------------------------------------

def test_rollback_republishes_old_bytes_as_a_new_traceable_version(db) -> None:
    rule_set = ruleset_service.ensure_baseline(db)
    old = ruleset_service.publish(db, rule_set, version="rel-a", published_by="alice")
    old_bytes = old.package
    ruleset_service.publish(db, rule_set, version="rel-b", published_by="alice")

    rolled = ruleset_service.rollback(db, rule_set, to_version="rel-a", published_by="bob", changelog="回滚原因")

    assert rolled.version == "rel-a.rollback"
    assert rolled.origin_version == "rel-a"
    assert rolled.published_by == "bob"
    assert rolled.changelog == "回滚原因"
    # The old rules come back, relabelled with the new version so a probe that
    # reports "rel-a.rollback" matches the manifest it downloaded.
    assert json.loads(rolled.package.decode("utf-8"))["ruleset_version"] == "rel-a.rollback"
    assert rolled.rule_count == old.rule_count
    assert [rule["rule_id"] for rule in json.loads(rolled.package.decode("utf-8"))["rules"]] == \
        [rule["rule_id"] for rule in json.loads(old_bytes.decode("utf-8"))["rules"]]
    assert rolled.sha256 == hashlib.sha256(rolled.package).hexdigest()
    # History is preserved, not overwritten.
    assert db.get(RuleSetVersion, old.id).package == old_bytes
    assert db.get(RuleSet, rule_set.id).active_version_id == rolled.id


def test_a_second_rollback_to_the_same_version_gets_a_distinct_name(db) -> None:
    rule_set = ruleset_service.ensure_baseline(db)
    ruleset_service.publish(db, rule_set, version="rel-c", published_by="alice")
    first = ruleset_service.rollback(db, rule_set, to_version="rel-c", published_by="bob")
    second = ruleset_service.rollback(db, rule_set, to_version="rel-c", published_by="bob")
    assert first.version == "rel-c.rollback"
    assert second.version == "rel-c.rollback2"


def test_rollback_to_an_unknown_version_is_refused(db) -> None:
    rule_set = ruleset_service.ensure_baseline(db)
    with pytest.raises(RuleSetError, match="不存在"):
        ruleset_service.rollback(db, rule_set, to_version="does-not-exist")


# --- API -------------------------------------------------------------------

def _register_probe(client: TestClient, name: str) -> tuple[int, str]:
    response = client.post("/api/v1/probes/register",
                           json={"name": name, "hostname": name, "ip_address": "10.8.8.8", "metadata": {}})
    assert response.status_code == 200
    body = response.json()
    return body["id"], body["token"]


def test_rule_set_endpoints_are_listed_with_their_active_version() -> None:
    with TestClient(app) as client:
        body = client.get("/api/v1/rulesets").json()
        assert body["total"] >= 1
        rule_set = body["items"][0]
        assert rule_set["name"] == ruleset_service.DEFAULT_RULE_SET
        assert rule_set["active_version"]["version"] == BASELINE
        assert rule_set["working_rule_count"] > 0


def test_publishing_and_rolling_back_over_http() -> None:
    with TestClient(app) as client:
        rule_set_id = client.get("/api/v1/rulesets").json()["items"][0]["id"]
        published = client.post(f"/api/v1/rulesets/{rule_set_id}/versions",
                                json={"version": "http-1", "changelog": "首次发布"})
        assert published.status_code == 200, published.text
        assert published.json()["version"] == "http-1"

        # A published version is immutable: the same name is refused.
        duplicate = client.post(f"/api/v1/rulesets/{rule_set_id}/versions", json={"version": "http-1"})
        assert duplicate.status_code == 400
        assert "已存在" in duplicate.json()["detail"]

        rollback = client.post(f"/api/v1/rulesets/{rule_set_id}/rollback",
                               json={"to_version": BASELINE, "changelog": "回到基线"})
        assert rollback.status_code == 200, rollback.text
        assert rollback.json()["origin_version"] == BASELINE

        versions = client.get(f"/api/v1/rulesets/{rule_set_id}/versions").json()
        assert {item["version"] for item in versions["items"]} >= {BASELINE, "http-1"}


def test_an_invalid_publish_request_is_rejected_without_publishing() -> None:
    with TestClient(app) as client:
        rule_set_id = client.get("/api/v1/rulesets").json()["items"][0]["id"]
        before = client.get(f"/api/v1/rulesets/{rule_set_id}/versions").json()["total"]
        response = client.post(f"/api/v1/rulesets/{rule_set_id}/versions",
                               json={"version": "bad name with spaces"})
        assert response.status_code == 400
        assert client.get(f"/api/v1/rulesets/{rule_set_id}/versions").json()["total"] == before


def test_probe_rule_endpoints_require_a_probe_token() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "ruleset-probe-auth")
        # No credentials at all. Development mode answers 403 (the probe id cannot
        # be resolved without a token); production answers 401. Either way the
        # request must not be served - being listed as a probe API only means
        # "no admin session required", never "no authentication".
        assert client.get(f"/api/v1/probes/{probe_id}/ruleset/manifest").status_code in (401, 403)
        assert client.get(f"/api/v1/probes/{probe_id}/ruleset").status_code in (401, 403)
        # A token minted for a different probe is refused too.
        other_id, other_token = _register_probe(client, "ruleset-probe-wrong-token")
        wrong = client.get(f"/api/v1/probes/{probe_id}/ruleset/manifest",
                           headers={"X-Probe-ID": str(other_id), "X-Probe-Token": other_token})
        assert wrong.status_code == 403
        # A valid header set, so the 401 above is about authentication not routing.
        ok = client.get(f"/api/v1/probes/{probe_id}/ruleset/manifest",
                        headers={"X-Probe-ID": str(probe_id), "X-Probe-Token": token})
        assert ok.status_code == 200


def test_one_probe_cannot_read_another_probes_ruleset() -> None:
    with TestClient(app) as client:
        first_id, first_token = _register_probe(client, "ruleset-owner")
        second_id, _ = _register_probe(client, "ruleset-other")
        response = client.get(f"/api/v1/probes/{second_id}/ruleset/manifest",
                              headers={"X-Probe-ID": str(first_id), "X-Probe-Token": first_token})
        assert response.status_code == 403


def test_probe_download_returns_the_exact_published_bytes() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "ruleset-byte-probe")
        headers = {"X-Probe-ID": str(probe_id), "X-Probe-Token": token}
        manifest = client.get(f"/api/v1/probes/{probe_id}/ruleset/manifest", headers=headers).json()
        row = manifest["manifest"]

        response = client.get(f"/api/v1/probes/{probe_id}/ruleset", headers=headers)
        assert response.status_code == 200
        assert hashlib.sha256(response.content).hexdigest() == row["sha256"]
        assert len(response.content) == row["size"] == manifest["manifest"]["size"]
        assert response.headers["X-RuleSet-Sha256"] == row["sha256"]
        assert response.headers["X-RuleSet-Version"] == row["ruleset_version"]
        # What a probe would load is exactly what was published.
        assert json.loads(response.content.decode("utf-8"))["ruleset_version"] == row["ruleset_version"]


def test_manifest_tells_a_current_probe_not_to_download_again() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "ruleset-current-probe")
        headers = {"X-Probe-ID": str(probe_id), "X-Probe-Token": token}
        stale = client.get(f"/api/v1/probes/{probe_id}/ruleset/manifest?current=very-old", headers=headers).json()
        assert stale["up_to_date"] is False
        fresh = client.get(
            f"/api/v1/probes/{probe_id}/ruleset/manifest?current={stale['active_version']}", headers=headers).json()
        assert fresh["up_to_date"] is True


def test_an_old_probe_is_refused_a_pack_that_requires_a_newer_agent() -> None:
    with TestClient(app) as client:
        rule_set_id = client.get("/api/v1/rulesets").json()["items"][0]["id"]
        published = client.post(f"/api/v1/rulesets/{rule_set_id}/versions",
                                json={"version": "needs-4", "min_agent_version": "4.0.0"})
        assert published.status_code == 200, published.text
        probe_id, token = _register_probe(client, "ruleset-old-probe")
        headers = {"X-Probe-ID": str(probe_id), "X-Probe-Token": token, "X-Agent-Version": "3.3.1"}
        response = client.get(f"/api/v1/probes/{probe_id}/ruleset?version=needs-4", headers=headers)
        assert response.status_code == 409
        # Refused, not silently downgraded to something else.
        assert "最小版本" in response.json()["detail"]
        # Restore the baseline so later tests read the same active version.
        client.post(f"/api/v1/rulesets/{rule_set_id}/rollback", json={"to_version": BASELINE})


def test_downloading_an_unknown_version_is_a_404() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "ruleset-404-probe")
        headers = {"X-Probe-ID": str(probe_id), "X-Probe-Token": token}
        assert client.get(f"/api/v1/probes/{probe_id}/ruleset?version=nope", headers=headers).status_code == 404


def test_a_legacy_probe_heartbeat_still_works_without_the_new_fields() -> None:
    """A 3.3.1 probe sends no capability fields and must still be answered."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "ruleset-legacy-heartbeat")
        headers = {"X-Probe-ID": str(probe_id), "X-Probe-Token": token}
        response = client.post(f"/api/v1/probes/{probe_id}/heartbeat", json={"status": "online"}, headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        # The platform advertises the version it has; an older probe ignores it.
        assert body["latest_ruleset_version"]


def test_heartbeat_reports_the_latest_ruleset_version_to_a_new_probe() -> None:
    from app.api.v1 import _latest_ruleset_version

    session = SessionLocal()
    try:
        assert _latest_ruleset_version(session)
    finally:
        session.close()
