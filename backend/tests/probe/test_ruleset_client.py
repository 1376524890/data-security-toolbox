"""Probe-side rule hot update: bounded, verified, atomic, never fatal.

The probe is the untrusted end of the rule flow, so every failure mode has to
leave it running on a known-good pack instead of taking the agent down with it.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[3]))

from probe import ruleset_client  # noqa: E402
from probe.ruleset_client import RuleSetClient, RuleSetUpdateError, SOURCE_BUILTIN, SOURCE_SERVER  # noqa: E402
from shared.sensitive_detection import build_engine  # noqa: E402
from shared.sensitive_detection.ruleset import pack_digest  # noqa: E402

AGENT_VERSION = "3.3.1"
SERVER_RULES = [
    {"rule_id": "phone-srv", "name": "手机号", "entity": "PHONE", "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)",
     "confidence": 0.9, "validator": "cn_mobile", "enabled": True, "rule_source": "builtin", "level": "L3"},
]


def _pack(version: str = "srv-1", *, rules: list[dict] | None = None, engine_version: str = "1.0.0",
          min_agent_version: str = "", schema_version: str = "1.0") -> bytes:
    document = {
        "schema_version": schema_version,
        "ruleset_version": version,
        "engine_version": engine_version,
        "min_agent_version": min_agent_version,
        "rules": SERVER_RULES if rules is None else rules,
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")


class _Server:
    """Minimal stand-in for the two probe rule endpoints."""

    def __init__(self, payload: bytes, version: str = "srv-1", *, digest: str | None = None,
                 size: int | None = None, up_to_date: bool = False,
                 download_error: Exception | None = None) -> None:
        self.payload = payload
        self.version = version
        self.digest = digest if digest is not None else pack_digest(payload)
        self.size = size if size is not None else len(payload)
        self.up_to_date = up_to_date
        self.download_error = download_error
        self.downloads = 0

    def manifest_url(self, current: str) -> str:
        return f"https://platform.test/api/v1/probes/1/ruleset/manifest?current={current}"

    def download_url(self, version: str) -> str:
        return f"https://platform.test/api/v1/probes/1/ruleset?version={version}"

    def fetch_json(self, url: str) -> dict:
        return {
            "active_version": self.version,
            "up_to_date": self.up_to_date,
            "manifest": {"ruleset_version": self.version, "sha256": self.digest, "size": self.size},
        }

    def fetch_bytes(self, url: str, limit: int) -> bytes:
        self.downloads += 1
        if self.download_error is not None:
            raise self.download_error
        return self.payload


def _client(tmp_path: Path, server: _Server, **overrides) -> RuleSetClient:
    kwargs = {
        "directory": tmp_path / "rules",
        "fetch_json": server.fetch_json,
        "fetch_bytes": server.fetch_bytes,
        "manifest_url": server.manifest_url,
        "download_url": server.download_url,
        "agent_version": AGENT_VERSION,
        "max_pack_bytes": 2 * 1024 * 1024,
        "self_test_timeout": 2.0,
        "enabled": True,
    }
    kwargs.update(overrides)
    return RuleSetClient(**kwargs)


def _retarget(client: RuleSetClient, server: _Server) -> None:
    """Point an existing client at a new stand-in server."""
    client._fetch_json = server.fetch_json
    client._fetch_bytes = server.fetch_bytes


def test_never_synced_probe_runs_the_in_package_snapshot(tmp_path: Path) -> None:
    client = _client(tmp_path, _Server(_pack()))
    assert client.load_usable() == SOURCE_BUILTIN
    assert client.status.source == SOURCE_BUILTIN
    assert client.status.rule_count > 0
    # It must not invent a server version it never received.
    assert client.status.version.startswith("builtin-")


def test_successful_sync_switches_rules_without_a_restart(tmp_path: Path) -> None:
    payload = _pack("srv-7")
    server = _Server(payload, version="srv-7")
    client = _client(tmp_path, server)
    client.load_usable()
    assert client.status.version.startswith("builtin-")

    status = client.sync()

    assert status.version == "srv-7"
    assert status.source == SOURCE_SERVER
    assert status.sha256 == pack_digest(payload)
    assert status.updated_count == 1
    assert status.last_error == ""
    assert client.current_file.is_file()
    # The pinned snapshot for the next task is the newly loaded pack.
    assert client.snapshot_version() == "srv-7"
    assert {rule["rule_id"] for rule in client.engine_snapshot().rules} == {"phone-srv"}
    # State survives a process restart.
    reopened = _client(tmp_path, _Server(_pack("srv-99")))
    assert reopened.load_usable() == "current"
    assert reopened.status.version == "srv-7"


def test_already_current_version_does_not_download_again(tmp_path: Path) -> None:
    server = _Server(_pack("srv-7"), version="srv-7", up_to_date=True)
    client = _client(tmp_path, server)
    client.load_usable()
    client.sync()
    assert server.downloads == 0
    assert client.status.last_error == ""


def test_wrong_sha256_is_refused_and_previous_rules_stay(tmp_path: Path) -> None:
    client = _client(tmp_path, _Server(_pack("srv-7"), version="srv-7"))
    client.load_usable()
    client.sync()
    good_rules = {rule["rule_id"] for rule in client.engine_snapshot().rules}

    _retarget(client, _Server(_pack("srv-8"), version="srv-8", digest="0" * 64))
    status = client.sync()

    assert "SHA256" in status.last_error
    assert status.version == "srv-7"
    assert {rule["rule_id"] for rule in client.engine_snapshot().rules} == good_rules


def test_malformed_schema_is_refused_without_touching_the_cache(tmp_path: Path) -> None:
    client = _client(tmp_path, _Server(_pack("srv-7"), version="srv-7"))
    client.load_usable()
    client.sync()
    before = client.current_file.read_bytes()

    broken = b'{"ruleset_version": "srv-8", "rules": "not-a-list"}'
    _retarget(client, _Server(broken, version="srv-8"))
    status = client.sync()

    assert status.last_error
    assert client.current_file.read_bytes() == before
    assert status.version == "srv-7"


def test_oversized_pack_is_refused_before_downloading(tmp_path: Path) -> None:
    payload = _pack("srv-8")
    server = _Server(payload, version="srv-8", size=8 * 1024 * 1024)
    client = _client(tmp_path, server)
    client.load_usable()
    status = client.sync()

    assert "超过探针上限" in status.last_error
    assert server.downloads == 0


def test_incompatible_engine_version_is_refused(tmp_path: Path) -> None:
    _retarget_client = _client(tmp_path, _Server(_pack("srv-8", engine_version="9.0.0"), version="srv-8"))
    _retarget_client.load_usable()
    status = _retarget_client.sync()
    assert status.last_error
    assert status.source == SOURCE_BUILTIN


def test_min_agent_version_gate_refuses_a_pack_for_a_newer_agent(tmp_path: Path) -> None:
    client = _client(tmp_path, _Server(_pack("srv-8", min_agent_version="4.0.0"), version="srv-8"))
    client.load_usable()
    status = client.sync()
    assert status.last_error
    # The built-in pack is still the loaded one.
    assert status.version.startswith("builtin-")


def test_interrupted_download_keeps_the_running_rules(tmp_path: Path) -> None:
    client = _client(tmp_path, _Server(_pack("srv-7"), version="srv-7"))
    client.load_usable()
    client.sync()

    _retarget(client, _Server(_pack("srv-8"), version="srv-8", download_error=OSError("connection reset")))
    status = client.sync()

    assert "connection reset" in status.last_error
    assert status.version == "srv-7"
    # A half-finished update must not leave a staging directory that claims to be current.
    assert not (client.directory / ruleset_client.STAGING).exists()


def test_a_corrupted_cached_pack_falls_back_to_the_previous_one(tmp_path: Path) -> None:
    client = _client(tmp_path, _Server(_pack("srv-7"), version="srv-7"))
    client.load_usable()
    client.sync()
    assert client.current_file.is_file()
    (client.directory / ruleset_client.PREVIOUS).mkdir(parents=True, exist_ok=True)
    client.previous_file.write_bytes(_pack("srv-6"))
    # Corrupt the current copy the way a torn write or a truncated disk would.
    client.current_file.write_bytes(b"{not json at all")

    reopened = _client(tmp_path, _Server(_pack("srv-9"), version="srv-9"))
    assert reopened.load_usable() == "previous"
    assert reopened.status.version == "srv-6"
    assert reopened.status.last_error


def test_unusable_rule_pack_is_refused_rather_than_partially_applied(tmp_path: Path) -> None:
    rules = [{"rule_id": "empty-matcher", "entity": "PHONE", "pattern": ".*", "enabled": True}]
    client = _client(tmp_path, _Server(_pack("srv-8", rules=rules), version="srv-8"))
    client.load_usable()
    status = client.sync()
    assert status.last_error
    assert status.version.startswith("builtin-")


def test_an_unknown_validator_is_refused_rather_than_ignored(tmp_path: Path) -> None:
    rules = [{"rule_id": "typed", "entity": "PHONE", "pattern": r"1[3-9]\d{9}",
              "validator": "no_such_validator", "enabled": True}]
    client = _client(tmp_path, _Server(_pack("srv-8", rules=rules), version="srv-8"))
    client.load_usable()
    status = client.sync()
    assert status.last_error
    assert status.version.startswith("builtin-")


def test_a_catastrophic_pattern_is_bounded_instead_of_hanging_the_probe(tmp_path: Path) -> None:
    rules = [
        {"rule_id": "phone-srv", "entity": "PHONE", "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)",
         "validator": "cn_mobile", "enabled": True},
        {"rule_id": "hostile", "entity": "EMAIL", "pattern": r"(a+)+$", "enabled": True},
    ]
    engine = build_engine(rules, timeout=0.05)
    started = time.monotonic()
    engine.scan_text("a" * 200_000 + "!", source_type="text")
    elapsed = time.monotonic() - started

    # Bounded per rule rather than unbounded backtracking.
    assert elapsed < 5.0
    assert engine.last_report.timeouts
    # And the good rule still works on the same text.
    assert engine.scan_text("联系 13800138000", source_type="text")


def test_external_packs_are_refused_without_a_timeout_capable_backend(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ruleset_client, "SUPPORTS_TIMEOUT", False)
    server = _Server(_pack("srv-8"), version="srv-8")
    client = _client(tmp_path, server)
    client.load_usable()
    status = client.sync()

    assert "不支持超时" in status.last_error
    assert server.downloads == 0
    assert status.version.startswith("builtin-")


def test_disabled_hot_update_never_calls_the_server(tmp_path: Path) -> None:
    server = _Server(_pack("srv-8"), version="srv-8")

    def _explode(url: str) -> dict:
        raise AssertionError("disabled hot update must not call the server")

    client = _client(tmp_path, server, enabled=False)
    client._fetch_json = _explode
    client.load_usable()
    client.sync()
    assert server.downloads == 0


def test_manifest_without_a_version_is_reported_not_swallowed(tmp_path: Path) -> None:
    client = _client(tmp_path, _Server(_pack("srv-8")))
    client._fetch_json = lambda url: {"up_to_date": False, "manifest": {}}
    client.load_usable()
    status = client.sync()
    assert "缺少版本或摘要" in status.last_error


def test_heartbeat_payload_explains_running_on_builtin_rules(tmp_path: Path) -> None:
    client = _client(tmp_path, _Server(_pack()))
    client.load_usable()
    payload = client.status.to_dict()
    caps = client.capabilities()

    assert payload["ruleset_source"] == SOURCE_BUILTIN
    assert payload["current_ruleset_version"].startswith("builtin-")
    assert caps["ruleset_hot_update"] is True
    assert caps["regex_timeout"] is True
    assert caps["rule_count"] > 0


def test_a_superseded_pack_is_kept_so_a_bad_update_can_be_reversed(tmp_path: Path) -> None:
    client = _client(tmp_path, _Server(_pack("srv-7"), version="srv-7"))
    client.load_usable()
    client.sync()

    _retarget(client, _Server(_pack("srv-8"), version="srv-8"))
    status = client.sync()

    assert status.version == "srv-8"
    assert json.loads(client.previous_file.read_text(encoding="utf-8"))["ruleset_version"] == "srv-7"


def test_update_error_is_a_plain_exception_type() -> None:
    assert issubclass(RuleSetUpdateError, RuntimeError)
    with pytest.raises(RuleSetUpdateError):
        raise RuleSetUpdateError("x")
