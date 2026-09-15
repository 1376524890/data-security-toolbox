import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api import deployments as deployments_module
from app.core.database import SessionLocal
from app.deployment.credential import encrypt_credential
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
