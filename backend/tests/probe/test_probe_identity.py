from __future__ import annotations

import json
import os
import stat
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[3]))

import probe.probe as probe  # noqa: E402


def _make_config(tmp_path: Path, bootstrap: str = "boot") -> probe.Config:
    config = probe.Config(Path("/tmp/nonexistent-probe.toml"))
    config.agent["identity_path"] = str(tmp_path / "probe.identity.json")
    config.agent["token_path"] = str(tmp_path / "probe.token")
    config.spool["path"] = str(tmp_path / "spool")
    config.agent["bootstrap_token"] = bootstrap
    config.agent["allow_auto_reenroll"] = False
    return config


def test_first_registration_persists_identity(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    calls = {"n": 0}

    def fake_register(url, payload, headers, cfg, timeout=30):
        calls["n"] += 1
        assert headers.get("X-Probe-Bootstrap-Token") == "boot"
        return {"id": 12, "token": "tok-abc123"}

    probe.http_json = fake_register
    agent = probe.ProbeAgent(config)
    agent.register()
    assert calls["n"] == 1
    assert agent.probe_id == 12
    assert agent.token == "tok-abc123"
    identity_file = Path(config.agent["identity_path"])
    assert identity_file.exists()
    data = json.loads(identity_file.read_text())
    assert data["probe_id"] == 12
    assert data["token"] == "tok-abc123"
    assert data["registered_at"]
    assert data["server"] == config.base_url()
    mode = stat.S_IMODE(identity_file.stat().st_mode)
    assert mode == 0o600
    dir_mode = stat.S_IMODE(identity_file.parent.stat().st_mode)
    assert dir_mode == 0o700


def test_restart_reuses_existing_identity_no_rotation(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    probe.http_json = lambda *a, **k: {"id": 12, "token": "tok-abc123"}
    first = probe.ProbeAgent(config)
    first.register()

    # Simulate a restart: a fresh agent must NOT call register or rotate token.
    def fail_register(*a, **k):
        raise AssertionError("register should not be called on restart")

    probe.http_json = fail_register
    second = probe.ProbeAgent(_make_config(tmp_path))
    second.register()
    assert second.probe_id == 12
    assert second.token == "tok-abc123"


def test_missing_identity_and_no_bootstrap_raises(tmp_path: Path) -> None:
    config = _make_config(tmp_path, bootstrap="")
    agent = probe.ProbeAgent(config)
    with pytest.raises(RuntimeError):
        agent.register()


def test_corrupt_identity_treated_as_missing(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    identity_file = Path(config.agent["identity_path"])
    identity_file.parent.mkdir(parents=True, exist_ok=True)
    identity_file.write_text("{not valid json", encoding="utf-8")
    ident = probe.ProbeIdentity(identity_file)
    assert ident.exists() is False
    assert ident.probe_id is None


def test_atomic_manifest_leaves_no_tmp(tmp_path: Path) -> None:
    path = tmp_path / "segment.json"
    probe.write_spool_metadata_atomic(path, {"state": probe.STATE_PENDING, "sequence": 3})
    assert path.exists()
    assert not (tmp_path / "segment.json.tmp").exists()
    assert json.loads(path.read_text())["sequence"] == 3


def test_sequence_restored_from_spool(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    spool = Path(config.spool["path"])
    spool.mkdir(parents=True, exist_ok=True)
    (spool / "seg-000005.json").write_text(json.dumps({"sequence": 5}))
    agent = probe.ProbeAgent(config)
    assert agent.sequence == 5


def _seed_segment(config: probe.Config, tmp_path: Path, state: str = probe.STATE_PENDING) -> Path:
    spool = Path(config.spool["path"])
    spool.mkdir(parents=True, exist_ok=True)
    (spool / "seg.pcapng").write_bytes(b"\x00fake")
    meta = {"state": state, "sequence": 1, "attempts": 0}
    meta_path = spool / "seg.json"
    probe.write_spool_metadata_atomic(meta_path, meta)
    return meta_path


def test_upload_fsm_transient_retry_then_success(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    (Path(config.agent["identity_path"])).parent.mkdir(parents=True, exist_ok=True)
    probe.ProbeIdentity(Path(config.agent["identity_path"])).save(5, "tok", probe.now_iso(), config.base_url())
    agent = probe.ProbeAgent(config)
    meta_path = _seed_segment(config, tmp_path)
    attempts = {"n": 0}

    def flaky_upload(path, metadata, probe_id, token, cfg, timeout=120):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise urllib.error.HTTPError("http://x", 503, "service unavailable", {}, None)
        return {"id": 9, "task_id": 42}

    probe.http_upload = flaky_upload
    metadata = probe.spool_metadata(meta_path)
    assert agent._process_upload(meta_path, metadata) is False
    after = probe.spool_metadata(meta_path)
    assert after["state"] == probe.STATE_RETRY_WAIT
    assert after["attempts"] == 1
    assert after["next_attempt_at"]
    # Clear the backoff so the next attempt is eligible.
    after["next_attempt_at"] = 0
    probe.write_spool_metadata_atomic(meta_path, after)
    assert agent._process_upload(meta_path, probe.spool_metadata(meta_path)) is True
    done = probe.spool_metadata(meta_path)
    assert done["state"] == probe.STATE_UPLOADED
    assert done["backend_id"] == 9
    assert done["task_id"] == 42
    assert done["uploaded_at"]


def test_upload_fsm_auth_error(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    probe.ProbeIdentity(Path(config.agent["identity_path"])).save(5, "tok", probe.now_iso(), config.base_url())
    agent = probe.ProbeAgent(config)
    meta_path = _seed_segment(config, tmp_path)
    probe.http_upload = lambda *a, **k: (_ for _ in ()).throw(urllib.error.HTTPError("http://x", 401, "unauthorized", {}, None))
    assert agent._process_upload(meta_path, probe.spool_metadata(meta_path)) is False
    after = probe.spool_metadata(meta_path)
    assert after["state"] == probe.STATE_AUTH_ERROR
    assert agent.auth_error is True
    assert agent.upload_status == probe.STATE_AUTH_ERROR


def test_upload_fsm_quarantine_permanent(tmp_path: Path) -> None:
    config = _make_config(tmp_path)
    probe.ProbeIdentity(Path(config.agent["identity_path"])).save(5, "tok", probe.now_iso(), config.base_url())
    agent = probe.ProbeAgent(config)
    meta_path = _seed_segment(config, tmp_path)
    probe.http_upload = lambda *a, **k: (_ for _ in ()).throw(urllib.error.HTTPError("http://x", 400, "bad request", {}, None))
    assert agent._process_upload(meta_path, probe.spool_metadata(meta_path)) is False
    after = probe.spool_metadata(meta_path)
    assert after["state"] == probe.STATE_QUARANTINED


def test_drop_metrics_unavailable_when_no_counters() -> None:
    result = probe.parse_capture_drop_metrics("some random stderr", "dumpcap")
    assert result["drop_metric_available"] is False
    assert result["packets_dropped"] is None


def test_drop_metrics_dumpcap() -> None:
    result = probe.parse_capture_drop_metrics("100 packets captured, 3 packets dropped by interface", "dumpcap")
    assert result["drop_metric_available"] is True
    assert result["packets_received"] == 100
    assert result["packets_dropped"] == 3
    assert result["drop_rate"] == 0.03


def test_capture_tool_format(monkeypatch) -> None:
    monkeypatch.setattr(probe.shutil, "which", lambda name: "/usr/bin/dumpcap" if name == "dumpcap" else "")
    config = probe.Config(Path("/tmp/nonexistent.toml"))
    assert probe.detect_capture_tool(config) == ("dumpcap", ".pcapng")
    monkeypatch.setattr(probe.shutil, "which", lambda name: "/usr/sbin/tcpdump" if name == "tcpdump" else "")
    assert probe.detect_capture_tool(config) == ("tcpdump", ".pcap")
