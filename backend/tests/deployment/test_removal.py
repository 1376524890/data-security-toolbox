"""Removing a probe from a target host, and the record that proves it happened.

The removal has to be trustworthy in both directions: it must actually delete
what the installer created, and it must not claim to have done so when it did
not. These tests pin the command that reaches the host, the audit trail that
comes back, and the platform-side cleanup that follows a clean removal.
"""

import secrets
from pathlib import Path
from unittest.mock import Mock

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api import deployments as deployments_module
from app.api import probes as probes_module
from app.core.database import SessionLocal
from app.deployment import removal, service
from app.deployment.credential import encrypt_credential
from app.main import app
from app.models import Probe, ProbeDeployment, ProbeDeploymentCredential, ProbeDeploymentEvent

SUMMARY = (
    'DST_UNINSTALL {"ok":true,"dry_run":0,"removed":["spool","probe-dir","config-dir"],'
    '"absent":["systemd-unit"],"kept":[],"failed":[],"bytes_freed":4096,"files_freed":12}'
)
PARTIAL = (
    'DST_UNINSTALL {"ok":false,"dry_run":0,"removed":["spool"],"absent":[],"kept":[],'
    '"failed":["probe-dir"],"bytes_freed":1024,"files_freed":3}'
)


def _removal_row(db, **overrides) -> int:
    row = ProbeDeployment(
        name="remove-10.8.0.1",
        action="uninstall",
        host=overrides.pop("host", "10.8.0.1"),
        port=22,
        username=overrides.pop("username", "root"),
        auth_type="password",
        status=overrides.pop("status", "CREATED"),
        current_stage="queued",
        # The suite shares one database, so every row needs its own key.
        idempotency_key=overrides.pop("idempotency_key", f"removal-{secrets.token_hex(8)}"),
        **overrides,
    )
    db.add(row)
    db.flush()
    ciphertext, nonce, key_id, expires = encrypt_credential(row.id, "password", "test-password", 3600)
    db.add(
        ProbeDeploymentCredential(
            deployment_id=row.id,
            encrypted_secret=ciphertext,
            nonce=nonce,
            key_id=key_id,
            expires_at=expires,
        )
    )
    db.commit()
    return row.id


def _fake_ssh(monkeypatch, tmp_path: Path, stdout: str = SUMMARY, rc: int = 0, username: str = "root"):
    """Stand in for the target host and record every command sent to it."""
    ssh = Mock(username=username)
    commands: list[str] = []

    def execute(command, **kwargs):
        commands.append(command)
        if command.startswith("mktemp"):
            return 0, "/tmp/dstprobe-deploy-abcd\n", ""
        if "uninstall.sh" in command:
            return rc, stdout, "uninstaller noise"
        return 0, "", ""

    ssh.exec.side_effect = execute
    monkeypatch.setattr(service, "SshClient", Mock(return_value=ssh))
    monkeypatch.setattr(removal, "find_uninstaller", lambda version=None: tmp_path / "uninstall.sh")
    return ssh, commands


def _credential_rows(db, deployment_id: int) -> list[ProbeDeploymentCredential]:
    """Read the credential table directly: the session caches relationships."""
    return list(
        db.scalars(
            select(ProbeDeploymentCredential).where(
                ProbeDeploymentCredential.deployment_id == deployment_id
            )
        )
    )


def test_removal_options_map_to_uninstaller_flags() -> None:
    row = ProbeDeployment(name="n", host="h", idempotency_key="flags")
    assert removal.RemovalService._flags(row) == []
    row.removal_options = {"keep_data": True, "keep_user": True, "remove_user": False}
    assert removal.RemovalService._flags(row) == ["--keep-data", "--keep-user"]
    row.removal_options = {"remove_user": True}
    assert removal.RemovalService._flags(row) == ["--remove-user"]


def test_removal_never_runs_against_an_install_row(monkeypatch, tmp_path) -> None:
    """A task dispatched at the wrong row must not delete anything."""
    ssh, _ = _fake_ssh(monkeypatch, tmp_path)
    with SessionLocal() as db:
        row = ProbeDeployment(
            name="deploy", host="10.8.9.9", username="root", auth_type="password",
            action="install", status="CREATED", idempotency_key="not-a-removal",
        )
        db.add(row)
        db.commit()
        removal.RemovalService(db, row.id).run()
        assert db.get(ProbeDeployment, row.id).status == "CREATED"
    assert not service.SshClient.called
    assert not ssh.exec.called


def test_root_run_removes_the_files_and_records_the_audit(monkeypatch, tmp_path) -> None:
    ssh, commands = _fake_ssh(monkeypatch, tmp_path)
    with SessionLocal() as db:
        deployment_id = _removal_row(db)
        removal.RemovalService(db, deployment_id).run()
        row = db.get(ProbeDeployment, deployment_id)
        assert row.status == "REMOVED"
        assert row.progress == 100
        assert row.current_stage == "REMOVED"
        assert row.error_code == ""
        assert row.result["ok"] is True
        assert row.result["removed"] == ["spool", "probe-dir", "config-dir"]
        assert row.result["bytes_freed"] == 4096
        assert row.result["files_freed"] == 12
        # The secret is gone whether the run succeeded or not.
        assert _credential_rows(db, deployment_id) == []
        assert row.credential_destroyed_at is not None
        # The console replays this trail while a removal is running, so the
        # stage sequence is part of the contract, not just the final status.
        stages = list(db.scalars(
            select(ProbeDeploymentEvent.stage)
            .where(ProbeDeploymentEvent.deployment_id == deployment_id)
            .order_by(ProbeDeploymentEvent.seq)
        ))
        assert stages == ["REMOVING", "REMOVED"]
        # Distinct sequences: the console reads the trail with ``seq > after``.
        seqs = list(db.scalars(
            select(ProbeDeploymentEvent.seq)
            .where(ProbeDeploymentEvent.deployment_id == deployment_id)
            .order_by(ProbeDeploymentEvent.id)
        ))
        assert seqs == [1, 2]
    uploaded = [command for command in commands if "uninstall.sh" in command]
    assert len(uploaded) == 1
    # A root connection is not wrapped in sudo, and the temp dir is cleaned up.
    assert uploaded[0] == "bash /tmp/dstprobe-deploy-abcd/uninstall.sh"
    assert commands[-1] == "rm -rf /tmp/dstprobe-deploy-abcd"


def test_non_root_run_uses_sudo_and_forwards_the_chosen_options(monkeypatch, tmp_path) -> None:
    _, commands = _fake_ssh(monkeypatch, tmp_path, username="operator")
    with SessionLocal() as db:
        deployment_id = _removal_row(
            db, username="operator", removal_options={"keep_data": True, "remove_user": True}
        )
        removal.RemovalService(db, deployment_id).run()
    uploaded = [command for command in commands if "uninstall.sh" in command]
    assert uploaded[0] == (
        "sudo -n bash /tmp/dstprobe-deploy-abcd/uninstall.sh --keep-data --remove-user"
    )


def test_partial_removal_is_reported_as_partial(monkeypatch, tmp_path) -> None:
    """What survived has to be visible, and a retry has to be possible."""
    _, commands = _fake_ssh(monkeypatch, tmp_path, stdout=PARTIAL, rc=2)
    with SessionLocal() as db:
        deployment_id = _removal_row(db, removal_options={"keep_data": False})
        removal.RemovalService(db, deployment_id).run()
        row = db.get(ProbeDeployment, deployment_id)
        assert row.status == "FAILED"
        assert row.error_code == "REMOVAL_PARTIAL"
        assert "spool" in row.error_message
        assert "probe-dir" in row.error_message
        assert row.result["ok"] is False
        assert _credential_rows(db, deployment_id) == []


def test_a_run_that_never_reached_the_summary_is_a_failure(monkeypatch, tmp_path) -> None:
    """No summary means the host state is unknown, so nothing may be claimed."""
    _, commands = _fake_ssh(monkeypatch, tmp_path, stdout="bash: line 1: root required", rc=1)
    with SessionLocal() as db:
        deployment_id = _removal_row(db)
        removal.RemovalService(db, deployment_id).run()
        row = db.get(ProbeDeployment, deployment_id)
        assert row.status == "FAILED"
        assert row.error_code == "REMOVAL_FAILED"
        assert row.result["ok"] is False
        assert row.result["reason"] == "uninstaller did not report a result"
    assert any("uninstall.sh" in command for command in commands)


def test_success_revokes_the_probe_token_and_keeps_the_record(monkeypatch, tmp_path) -> None:
    """A stripped host must not keep a working credential on the platform."""
    _fake_ssh(monkeypatch, tmp_path)
    with SessionLocal() as db:
        probe = Probe(name="revoke-me", ip_address="10.8.1.1", status="online", token="live", token_hash="hash")
        db.add(probe)
        db.commit()
        deployment_id = _removal_row(db, probe_id=probe.id)
        removal.RemovalService(db, deployment_id).run()
        db.refresh(probe)
        assert probe.token == "" and probe.token_hash == ""
        assert probe.status == "offline"
        assert db.get(ProbeDeployment, deployment_id).status == "REMOVED"


def test_success_can_drop_the_platform_record_in_the_same_step(monkeypatch, tmp_path) -> None:
    _fake_ssh(monkeypatch, tmp_path)
    with SessionLocal() as db:
        probe = Probe(name="drop-me", ip_address="10.8.2.2", status="online", token="live", token_hash="hash")
        db.add(probe)
        db.commit()
        probe_id = probe.id
        deployment_id = _removal_row(
            db, probe_id=probe_id, removal_options={"delete_record": True}
        )
        removal.RemovalService(db, deployment_id).run()
        assert db.get(Probe, probe_id) is None
        assert db.get(ProbeDeployment, deployment_id).status == "REMOVED"


def test_failed_removal_leaves_the_record_for_the_next_attempt(monkeypatch, tmp_path) -> None:
    _fake_ssh(monkeypatch, tmp_path, stdout=PARTIAL, rc=2)
    with SessionLocal() as db:
        probe = Probe(name="keep-me", ip_address="10.8.3.3", status="online", token="live", token_hash="hash")
        db.add(probe)
        db.commit()
        probe_id = probe.id
        deployment_id = _removal_row(
            db, probe_id=probe_id, removal_options={"delete_record": True}
        )
        removal.RemovalService(db, deployment_id).run()
        # The host still has files on it, so the address that finds it survives.
        assert db.get(Probe, probe_id) is not None
        assert db.get(ProbeDeployment, deployment_id).status == "FAILED"


def test_removal_api_creates_a_row_and_refuses_a_busy_host(monkeypatch) -> None:
    monkeypatch.setattr(deployments_module, "_dispatch", lambda deployment_id: None)
    payload = {
        "host": "10.8.4.4",
        "username": "root",
        "auth_type": "password",
        "password": "secret",
        "idempotency_key": "api-removal-1",
        "keep_data": True,
    }
    with TestClient(app) as client:
        created = client.post("/api/v1/probe-deployments/removal", json=payload)
        assert created.status_code == 202, created.text
        body = created.json()
        assert body["action"] == "uninstall"
        assert body["removal_options"] == {
            "keep_data": True, "keep_user": False, "remove_user": False, "delete_record": False,
        }
        # The same request is idempotent rather than a second SSH session.
        again = client.post("/api/v1/probe-deployments/removal", json=payload)
        assert again.json()["id"] == body["id"]
        busy = client.post(
            "/api/v1/probe-deployments/removal",
            json={**payload, "idempotency_key": "api-removal-2"},
        )
        assert busy.status_code == 409
        assert client.post(
            "/api/v1/probe-deployments/removal",
            json={**payload, "host": "10.8.4.5", "auth_type": "private_key", "password": None},
        ).status_code == 422
        # A row that still owns the host cannot be dropped from the history.
        assert client.delete(f"/api/v1/probe-deployments/{body['id']}").status_code == 409
        with SessionLocal() as db:
            row = db.get(ProbeDeployment, body["id"])
            assert row.credential is not None and row.credential.encrypted_secret
            row.status = "REMOVED"
            db.commit()
        # A finished one can.
        assert client.delete(f"/api/v1/probe-deployments/{body['id']}").status_code == 200
    with SessionLocal() as db:
        assert db.get(ProbeDeployment, body["id"]) is None


def test_delete_probe_can_strip_the_host_in_the_same_request(monkeypatch) -> None:
    monkeypatch.setattr(probes_module, "dispatch_probe_deployment", lambda deployment_id: None)
    with SessionLocal() as db:
        probe = Probe(name="one-step", ip_address="10.8.6.6", status="online", token="live", token_hash="hash")
        db.add(probe)
        db.commit()
        probe_id = probe.id
    with TestClient(app) as client:
        response = client.request(
            "DELETE",
            f"/api/v1/probes/{probe_id}",
            json={"remove_remote": True, "auth_type": "password", "password": "secret", "keep_user": True},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "queued"
        assert body["action"] == "uninstall"
        with SessionLocal() as db:
            row = db.get(ProbeDeployment, body["deployment_id"])
            assert row.action == "uninstall"
            # The address comes from what the platform already knows.
            assert row.host == "10.8.6.6"
            assert row.probe_id == probe_id
            assert row.removal_options == {
                "keep_data": False, "keep_user": True, "remove_user": False, "delete_record": True,
            }
            # The record survives until the host is actually clean.
            assert db.get(Probe, probe_id) is not None
        # Removing a host with no address to find it at is refused, not queued.
        with SessionLocal() as db:
            orphan = Probe(name="no-address", ip_address="", status="offline")
            db.add(orphan)
            db.commit()
            orphan_id = orphan.id
        refused = client.request(
            "DELETE",
            f"/api/v1/probes/{orphan_id}",
            json={"remove_remote": True, "auth_type": "password", "password": "secret"},
        )
        assert refused.status_code == 400


def test_platform_delete_failure_keeps_remote_success_and_destroys_credential(monkeypatch, tmp_path):
    _fake_ssh(monkeypatch, tmp_path)
    def failed_delete(db, probe_id):
        db.add(Probe(name=None))
        db.flush()  # Put the ORM session into a real failed-transaction state.
    monkeypatch.setattr(removal, 'delete_probe_record', failed_delete)
    with SessionLocal() as db:
        probe = Probe(name='platform-delete-failure', token='live', token_hash='hash')
        db.add(probe)
        db.commit()
        probe_id = probe.id
        deployment_id = _removal_row(db, probe_id=probe_id, removal_options={'delete_record': True})
        removal.RemovalService(db, deployment_id).run()
        row = db.get(ProbeDeployment, deployment_id)
        assert row.status == 'REMOVED'
        assert row.result['platform_record_deleted'] is False
        assert row.result['platform_record_error'] == 'database_error'
        assert _credential_rows(db, deployment_id) == []
        assert db.get(Probe, probe_id).token_hash == ''
