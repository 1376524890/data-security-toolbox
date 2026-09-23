import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api import deployments as deployments_module
from app.core.database import SessionLocal
from app.deployment.credential import encrypt_credential
from app.deployment.service import build_probe_toml
from app.deployment.enrollment import create_enrollment
from app.main import app
from app.models import ProbeDeployment, ProbeDeploymentCredential, ProbeEnrollment
from app.schemas import ProbeDeploymentCreate


def test_schema_mutual_exclusion() -> None:
    with pytest.raises(ValueError):
        ProbeDeploymentCreate(
            name="n",
            host="h",
            username="root",
            auth_type="password",
            password="pw",
            private_key="key",
            profile="standard",
            idempotency_key="ik",
        )


def test_create_deployment(monkeypatch) -> None:
    monkeypatch.setattr(deployments_module, "_dispatch", lambda deployment_id: None)
    with TestClient(app) as client:
        payload = {
            "name": "test-deploy",
            "host": "10.0.0.5",
            "port": 22,
            "username": "root",
            "auth_type": "password",
            "password": "secret",
            "profile": "standard",
            "idempotency_key": "api-key-1",
        }
        resp = client.post("/api/v1/probe-deployments", json=payload)
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "CREATED"
        with SessionLocal() as db:
            dep = db.get(ProbeDeployment, data["id"])
            assert dep is not None
            assert dep.credential is not None
            assert dep.credential.encrypted_secret


def test_register_consumes_enrollment_and_heartbeat_online() -> None:
    with SessionLocal() as db:
        dep = ProbeDeployment(
            name="deploy-x",
            host="10.0.0.6",
            username="root",
            auth_type="password",
            profile="standard",
            backend_url="https://platform.local",
            idempotency_key="api-key-2",
        )
        db.add(dep)
        db.commit()
        db.refresh(dep)
        dep_id = dep.id
        ciphertext, nonce, key_id, expires = encrypt_credential(dep_id, "password", "secret", 3600)
        db.add(ProbeDeploymentCredential(deployment_id=dep_id, encrypted_secret=ciphertext, nonce=nonce, key_id=key_id, expires_at=expires))
        token = create_enrollment(db, dep)

    with TestClient(app) as client:
        resp = client.post(
            "/api/v1/probes/register",
            json={"name": "host6", "hostname": "host6", "ip_address": "10.0.0.6", "deployment_id": dep_id},
            headers={"X-Probe-Bootstrap-Token": token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["deployment_id"] == dep_id
        probe_id = data["id"]
        probe_token = data["token"]

        replay = client.post(
            "/api/v1/probes/register",
            json={"name": "host6b", "hostname": "host6b", "ip_address": "10.0.0.6", "deployment_id": dep_id},
            headers={"X-Probe-Bootstrap-Token": token},
        )
        assert replay.status_code == 401

        hb = client.post(
            f"/api/v1/probes/{probe_id}/heartbeat",
            json={"status": "online", "metadata": {"agent_version": "3.2.0"}},
            headers={"X-Probe-ID": str(probe_id), "X-Probe-Token": probe_token},
        )
        assert hb.status_code == 200

    with SessionLocal() as db:
        dep = db.get(ProbeDeployment, dep_id)
        assert dep.status == "ONLINE"
        assert dep.probe_id == probe_id
        assert dep.first_heartbeat_at is not None
        enrollment = db.scalar(select(ProbeEnrollment).where(ProbeEnrollment.deployment_id == dep_id))
        assert enrollment.consumed_at is not None


def test_create_deployment_persists_data_asset_config(monkeypatch) -> None:
    monkeypatch.setattr(deployments_module, "_dispatch", lambda deployment_id: None)
    with TestClient(app) as client:
        payload = {
            "name": "test-deploy-data",
            "host": "10.0.0.9",
            "port": 22,
            "username": "root",
            "auth_type": "password",
            "password": "secret",
            "profile": "standard",
            "idempotency_key": "api-key-data-config",
            "data_paths": ["/srv/data", "/var/www/uploads"],
            "data_interval_seconds": 1800,
            "data_max_files": 300,
            "data_max_depth": 4,
            "data_include_databases": False,
        }
        resp = client.post("/api/v1/probe-deployments", json=payload)
        assert resp.status_code == 202
        body = resp.json()
        assert body["data_config"] == {
            "paths": ["/srv/data", "/var/www/uploads"],
            "interval_seconds": 1800,
            "max_files": 300,
            "max_depth": 4,
            "include_databases": False,
        }
        with SessionLocal() as db:
            dep = db.get(ProbeDeployment, body["id"])
            assert dep is not None
            assert dep.data_config["paths"] == ["/srv/data", "/var/www/uploads"]
            toml = build_probe_toml(dep, "bootstrap-token", None, interface="eth0")
    assert "[data]" in toml
    data_section = toml.split("[data]", 1)[1]
    assert "enabled = true" in data_section
    assert 'paths = ["/srv/data", "/var/www/uploads"]' in data_section
    assert "interval_seconds = 1800" in data_section
    assert "max_files = 300" in data_section
    assert "max_depth = 4" in data_section
    assert "include_databases = false" in data_section
    scan_section = toml.split("[scan]", 1)[1].split("[data]", 1)[0]
    assert "allow_remote = true" in scan_section


def test_zero_data_limits_survive_into_the_probe_config(monkeypatch) -> None:
    """0 = "no limit" must reach the probe as 0, not as the old 10000/3 cap.

    The regression this guards: the renderer read the values with ``or 10000`` /
    ``or 3``, so a deployment that deliberately asked for no cap was handed the
    legacy limits instead and its data inventory stopped three levels down.
    """
    monkeypatch.setattr(deployments_module, "_dispatch", lambda deployment_id: None)
    with TestClient(app) as client:
        payload = {
            "name": "test-deploy-unlimited-data",
            "host": "10.0.0.12",
            "port": 22,
            "username": "root",
            "auth_type": "password",
            "password": "secret",
            "profile": "standard",
            "idempotency_key": "api-key-unlimited-data",
            "data_paths": ["/srv/data"],
            "data_max_files": 0,
            "data_max_depth": 0,
            "data_include_databases": False,
        }
        body = client.post("/api/v1/probe-deployments", json=payload).json()
        with SessionLocal() as db:
            dep = db.get(ProbeDeployment, body["id"])
            toml = build_probe_toml(dep, "bootstrap-token", None, interface="eth0")
    data_section = toml.split("[data]", 1)[1]
    assert "max_files = 0" in data_section
    assert "max_depth = 0" in data_section
    agent_section = toml.split("[agent]", 1)[1].split("[scan]", 1)[0]
    assert "max_files = 0" in agent_section


def test_create_deployment_rejects_relative_data_paths(monkeypatch) -> None:
    monkeypatch.setattr(deployments_module, "_dispatch", lambda deployment_id: None)
    with TestClient(app) as client:
        payload = {
            "name": "test-deploy-bad-path",
            "host": "10.0.0.11",
            "username": "root",
            "auth_type": "password",
            "password": "secret",
            "profile": "standard",
            "idempotency_key": "api-key-bad-data-path",
            "data_paths": ["C:/Users/data", "/srv/../etc"],
        }
        resp = client.post("/api/v1/probe-deployments", json=payload)
        assert resp.status_code == 422
