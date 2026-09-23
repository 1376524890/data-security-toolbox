r"""The field samples that produced the false positives, kept as one baseline.

Every case here is a value that was really reported as sensitive data, or a real
value that must keep being reported. They are pinned together on purpose: a rule
edit, a pack import or a new default must not be able to bring one of them back
without a test going red.

The assertion is never "the pattern does not match" -- several of these match, and
that is fine, because a match is evidence. The assertion is that the platform
still refuses to make a *finding* out of them on its own, and that the real values
next to them still are findings.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import detection_gate, rule_library, scan_scope, sensitive_engine

#: The pattern that raised 331 Swedish organisation numbers on one host, at the
#: score its own pack reported for it.
ORGANISATION_NUMBER = r"\b\d{6}[-]?\d{4}\b"

#: The values it matched: a shell-history timestamp, a JSON mtime and a CGI
#: request id are all numbers, and a number is not an organisation number.
NOISE_SAMPLES = (": 1784680825:0; execute", '"mtime": 1756425477', "id=1784680825")

#: A database connection string whose host part looks like an address. The
#: host is not an email address, so the email rule must not claim it is.
CONNECTION_STRING = "postgresql://reader:secret@security@172.18.0.2:5432/app"

#: Source code that *names* a password without holding one: an annotated
#: parameter and a constructor call. Neither is a credential.
CODE_SHAPED_PASSWORDS = ("password: bytes,", "password = str(password)")


@pytest.fixture
def packaged_rule():
    """A pack rule in the (isolated) store, removed when the test ends."""
    written: list = []

    def write(rule_id: str, pattern: str, confidence: float) -> str:
        path = rule_library.rule_store_directory() / f"baseline-{uuid.uuid4().hex}.json"
        rule_library.atomic_json(path, {"rules": [{
            "id": rule_id, "name": "SeOrganisationsnummerRecognizer",
            "entity": "SE_ORGANISATIONSNUMMER", "pattern": pattern,
            "confidence": confidence, "source": "Presidio", "enabled": True,
        }]})
        written.append(path)
        return rule_id

    yield write
    for path in written:
        path.unlink(missing_ok=True)


def _hit(text: str, entity: str):
    name = sensitive_engine.legacy_name(entity) or entity
    for hit in sensitive_engine.scan_engine().scan_text(text):
        if (sensitive_engine.legacy_name(hit.entity) or str(hit.entity)) == name:
            return hit
    return None


# --- the data side -----------------------------------------------------------
def test_a_pack_rule_that_only_matches_digits_never_confirms(packaged_rule) -> None:
    packaged_rule("presidio-baseline-orgnr", ORGANISATION_NUMBER, 0.6)

    for sample in NOISE_SAMPLES:
        hit = _hit(sample, "SE_ORGANISATIONSNUMMER")
        assert hit is not None, sample          # the rule still looks at it ...
        assert not hit.confirmed, sample        # ... and still refuses to conclude
        assert detection_gate.derived_confidence("se_organisationsnummer", [{
            "category": "se_organisationsnummer", "rule_id": "presidio-baseline-orgnr",
            "evidence_type": "regex",
        }]) < detection_gate.confirm_threshold()


def test_a_connection_string_host_is_not_an_email_address() -> None:
    # ``security@172.18.0.2`` is the host part of a connection string; the rule's
    # validator rejects a "domain" that cannot be one.
    hit = _hit(CONNECTION_STRING, "EMAIL")

    assert hit is None or not hit.confirmed


def test_source_code_that_names_a_password_is_not_a_credential() -> None:
    for sample in CODE_SHAPED_PASSWORDS:
        hit = _hit(sample, "CREDENTIAL")
        assert hit is None or not hit.confirmed


def test_the_real_values_next_to_the_noise_are_still_findings() -> None:
    assert _hit("13800138000", "PHONE").confirmed
    assert _hit("someone@example.com", "EMAIL").confirmed


# --- the scope side ----------------------------------------------------------
def test_an_exact_request_for_the_platform_s_own_tree_is_refused() -> None:
    for path in (*scan_scope.OWN_TREE, "/opt/data-security-toolbox/engine/data_engine"):
        with pytest.raises(scan_scope.ScanScopeError):
            scan_scope.exclude_own_tree({"paths": [path], "exclude_paths": []})


def test_a_broader_scope_simply_never_walks_the_platform_s_own_tree() -> None:
    config = scan_scope.exclude_own_tree({"paths": ["/"], "exclude_paths": ["node_modules"]})

    assert config["exclude_paths"] == ["node_modules", *scan_scope.OWN_TREE]
    assert config["paths"] == ["/"]


def test_a_directory_that_merely_starts_with_the_same_name_is_still_scanned() -> None:
    config = scan_scope.exclude_own_tree(
        {"paths": ["/opt/data-security-toolbox-backup"], "exclude_paths": []}
    )

    assert config["paths"] == ["/opt/data-security-toolbox-backup"]


def test_the_queued_job_carries_the_narrowed_scope() -> None:
    with TestClient(app) as client:
        probe = client.post("/api/v1/probes/register", json={
            "name": "baseline-scope-probe", "hostname": "baseline-scope-probe",
            "ip_address": "10.9.7.9", "metadata": {}}).json()

        refused = client.post(f"/api/v1/probes/{probe['id']}/data-assets/jobs",
                              json={"paths": ["/opt/data-security-toolbox"]})
        assert refused.status_code == 400
        assert "工具箱自身目录" in refused.json()["detail"]

        queued = client.post(f"/api/v1/probes/{probe['id']}/data-assets/jobs",
                             json={"paths": ["/srv/customer"]})
        assert queued.status_code == 200
        task = client.get(f"/api/v1/tasks/{queued.json()['id']}").json()
        # The payload is the authoritative scope, and it says what was excluded.
        assert set(scan_scope.OWN_TREE) <= set(task["payload"]["config"]["exclude_paths"])
        assert task["payload"]["config"]["paths"] == ["/srv/customer"]
