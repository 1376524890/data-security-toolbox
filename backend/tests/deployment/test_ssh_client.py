"""Tests for SshClient managed known_hosts behavior."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock

import paramiko
import pytest

from app.core.config import settings
from app.deployment.ssh_client import SshClient, _TrustOnFirstUsePolicy


def _pending_line() -> str:
    return "192.168.191.128 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHLlmdWSqgXrQNEZcHQq3n3hTuLXhNlb+2yESNri/QJ2\n"


def test_managed_known_hosts_falls_back_to_storage(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "deployment_known_hosts", str(tmp_path / "readonly" / "known_hosts"))
    monkeypatch.setattr(settings, "storage_dir", tmp_path / "storage")
    client = SshClient("host")
    managed = client._managed_known_hosts()
    assert managed == tmp_path / "storage" / "deployment" / "known_hosts"


def test_managed_known_hosts_prefers_existing_configured(tmp_path, monkeypatch) -> None:
    configured = tmp_path / "deploy" / "known_hosts"
    configured.parent.mkdir(parents=True)
    configured.write_text(_pending_line())
    monkeypatch.setattr(settings, "deployment_known_hosts", str(configured))
    monkeypatch.setattr(settings, "storage_dir", tmp_path / "storage")
    client = SshClient("host")
    assert client._managed_known_hosts() == configured


def test_seed_known_hosts_from_pending(tmp_path, monkeypatch) -> None:
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "known_hosts.pending").write_text(_pending_line())
    monkeypatch.setattr(settings, "deployment_known_hosts", str(deploy / "known_hosts"))
    monkeypatch.setattr(settings, "storage_dir", tmp_path / "storage")
    client = SshClient("host")
    managed = client._managed_known_hosts()
    client._seed_known_hosts(managed)
    assert managed.exists()
    assert "192.168.191.128" in managed.read_text()


def test_connect_does_not_raise_missing_known_hosts(tmp_path, monkeypatch) -> None:
    """Regression: previously connect() raised 'no known_hosts configured'."""
    monkeypatch.setattr(settings, "deployment_known_hosts", str(tmp_path / "readonly" / "known_hosts"))
    monkeypatch.setattr(settings, "storage_dir", tmp_path / "storage")
    fake_client = Mock()
    fake_client._host_keys_filename = None
    monkeypatch.setattr(paramiko, "SSHClient", lambda: fake_client)
    client = SshClient("host")
    result = client.connect()
    assert result is client
    policy = fake_client.set_missing_host_key_policy.call_args.args[0]
    assert isinstance(policy, _TrustOnFirstUsePolicy)
    assert (tmp_path / "storage" / "deployment" / "known_hosts").exists()


def test_tofu_policy_persists_host_key(tmp_path) -> None:
    known_hosts = tmp_path / "known_hosts"
    host_keys = paramiko.HostKeys()
    fake_client = Mock()
    fake_client._host_keys = host_keys
    fake_client.save_host_keys.side_effect = lambda path: host_keys.save(path)
    policy = _TrustOnFirstUsePolicy(known_hosts)
    key = _load_key("10.0.0.1")
    policy.missing_host_key(fake_client, "10.0.0.1", key)
    assert known_hosts.exists()
    assert "10.0.0.1" in known_hosts.read_text()


def test_connect_verify_disabled_uses_autoadd(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "deployment_verify_host_key", False)
    fake_client = Mock()
    monkeypatch.setattr(paramiko, "SSHClient", lambda: fake_client)
    SshClient("host").connect()
    policy = fake_client.set_missing_host_key_policy.call_args.args[0]
    assert isinstance(policy, paramiko.AutoAddPolicy)


def _load_key(hostname: str) -> paramiko.PKey:
    seed = paramiko.HostKeys()
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".kh") as handle:
        handle.write(_pending_line().replace("192.168.191.128", hostname))
        path = handle.name
    try:
        seed.load(path)
    finally:
        os.unlink(path)
    return seed.lookup(hostname)["ssh-ed25519"]
