from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.deployment import service
from app.deployment.credential import encrypt_credential
from app.main import app
from app.models import ProbeDeployment, ProbeDeploymentCredential
from app.workers.deployment_tasks import sweep_deployment_timeouts


def test_missing_key_does_not_leave_active_task(monkeypatch):
    monkeypatch.setattr(settings, "deployment_secret_key", "")
    with TestClient(app) as client:
        response = client.post("/api/v1/probe-deployments", json={
            "host": "10.9.0.1", "username": "root", "password": "secret",
            "name": "probe", "idempotency_key": "missing-key",
        })
    assert response.status_code == 503
    with SessionLocal() as db:
        assert db.scalar(select(ProbeDeployment).where(ProbeDeployment.host == "10.9.0.1")) is None


@pytest.mark.parametrize("start_rc, expected", [(0, "WAIT_CALLBACK"), (1, "FAILED")])
def test_password_push_uses_sudo_and_checks_restart(monkeypatch, start_rc, expected):
    ssh = Mock(username="operator")
    commands = []
    def execute(command, **kwargs):
        commands.append(command)
        return (start_rc, "", "") if "systemctl restart" in command else (0, "", "")
    ssh.exec.side_effect = execute
    monkeypatch.setattr(service, "SshClient", Mock(return_value=ssh))
    monkeypatch.setattr(service, "run_preflight", lambda *args, **kwargs: {"compatible": True, "arch": "amd64", "interfaces": ["eth0"]})
    monkeypatch.setattr(service, "find_package", lambda arch: {"version": "3.2.0", "sha256": "digest"})
    monkeypatch.setattr(service.DeploymentService, "_remote_temp_dir", lambda *args: "/tmp/dstprobe-deploy-test")
    monkeypatch.setattr(service.DeploymentService, "_upload_package", lambda *args: None)
    monkeypatch.setattr(service.DeploymentService, "_upload_config", lambda *args: None)
    with SessionLocal() as db:
        dep = ProbeDeployment(name="probe", host=f"10.9.1.{start_rc + 1}", username="operator", auth_type="password", profile="standard", backend_url="https://platform.local", idempotency_key=f"sudo-{start_rc}")
        db.add(dep)
        db.flush()
        ciphertext, nonce, key_id, expires = encrypt_credential(dep.id, "password", "test-password", 3600)
        db.add(ProbeDeploymentCredential(deployment_id=dep.id, encrypted_secret=ciphertext, nonce=nonce, key_id=key_id, expires_at=expires))
        db.commit()
        service.DeploymentService(db, dep.id).run()
        db.refresh(dep)
        assert dep.status == expected
        assert dep.credential_destroyed_at is not None
        if start_rc:
            assert dep.error_code == "START_FAILED"
    assert any(command.startswith("sudo -n bash ") for command in commands)
    # A retry/upgrade must restart the unit: `systemctl start` is a no-op while a
    # probe is still running, which left the previous code and config live.
    assert "sudo -n systemctl restart data-security-toolbox-probe 2>&1" in commands
    assert not [command for command in commands if "systemctl start" in command]
    assert service.SshClient.call_args.kwargs["password"] == "test-password"


def test_registered_without_heartbeat_times_out():
    with SessionLocal() as db:
        dep = ProbeDeployment(name="timeout", host="10.9.2.1", username="root", auth_type="password", profile="standard", backend_url="https://platform.local", idempotency_key="heartbeat-timeout", status="REGISTERED", callback_deadline=datetime.now(UTC) - timedelta(seconds=1))
        db.add(dep)
        db.commit()
        dep_id = dep.id
    sweep_deployment_timeouts.run()
    with SessionLocal() as db:
        dep = db.get(ProbeDeployment, dep_id)
        assert dep.status == "FAILED"
        assert dep.error_code == "CALLBACK_TIMEOUT"
