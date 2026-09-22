"""A hand install must reconnect as the same deployment, not as a stranger.

The auto-deployment path is the platform reaching the host over SSH. When that
is blocked (firewall, no sudo, host off the platform's network) the operator
installs the packaged probe themselves — so the config the console hands them
has to enrol the probe against the deployment row that already exists.
"""
import re

from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models import ProbeDeployment


def _deployment(**overrides) -> int:
    with SessionLocal() as db:
        deployment = ProbeDeployment(
            name=overrides.pop("name", "manual-bootstrap"),
            host=overrides.pop("host", "10.0.0.44"),
            username="root",
            auth_type="password",
            profile="standard",
            backend_url="https://platform.local",
            idempotency_key=overrides.pop("idempotency_key", "manual-bootstrap-key"),
            **overrides,
        )
        db.add(deployment)
        db.commit()
        db.refresh(deployment)
        return deployment.id


def _token(toml: str) -> str:
    match = re.search(r'bootstrap_token = "([^"]+)"', toml)
    assert match, toml
    return match.group(1)


def test_manual_bootstrap_returns_an_installable_config_that_reconnects():
    deployment_id = _deployment()
    with TestClient(app) as client:
        resp = client.post(f"/api/v1/probe-deployments/{deployment_id}/manual-bootstrap")
        assert resp.status_code == 200
        body = resp.json()
        assert body["deployment_id"] == deployment_id
        assert body["backend_url"] == "https://platform.local"
        assert body["steps"], "the console must not have to invent the install steps"
        # The config is the same one the SSH push would have written.
        assert f"deployment_id = {deployment_id}" in body["toml"]
        assert "install.sh" in " ".join(body["steps"])

        # Installing by hand with this config enrols against this deployment.
        registered = client.post(
            "/api/v1/probes/register",
            json={"name": "hand-installed", "hostname": "host44",
                  "ip_address": "10.0.0.44", "deployment_id": deployment_id},
            headers={"X-Probe-Bootstrap-Token": _token(body["toml"])},
        )
        assert registered.status_code == 200
        assert registered.json()["deployment_id"] == deployment_id

    with SessionLocal() as db:
        deployment = db.get(ProbeDeployment, deployment_id)
        assert deployment.status == "REGISTERED"
        assert deployment.probe_id is not None

    with TestClient(app) as client:
        # Already connected: handing out a second token would be meaningless.
        assert client.post(
            f"/api/v1/probe-deployments/{deployment_id}/manual-bootstrap").status_code == 409


def test_manual_bootstrap_waits_while_the_worker_is_still_installing():
    deployment_id = _deployment(name="manual-installing", host="10.0.0.45",
                                idempotency_key="manual-installing", status="INSTALLING")
    with TestClient(app) as client:
        # A second token would invalidate the one the running install is about to use.
        assert client.post(
            f"/api/v1/probe-deployments/{deployment_id}/manual-bootstrap").status_code == 409


def test_manual_bootstrap_is_offered_for_a_callback_that_never_came():
    """The case the whole route exists for: pushed, installed, never called back."""
    deployment_id = _deployment(name="manual-wait", host="10.0.0.46",
                                idempotency_key="manual-wait", status="WAIT_CALLBACK")
    with TestClient(app) as client:
        resp = client.post(f"/api/v1/probe-deployments/{deployment_id}/manual-bootstrap")
        assert resp.status_code == 200
        assert _token(resp.json()["toml"])
