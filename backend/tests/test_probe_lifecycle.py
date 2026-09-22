"""A task-dedicated probe is retired only when it is provably safe to do so."""
import base64

import pytest

from app.core.config import settings
from app.core.database import SessionLocal
from app.deployment.record import store_credential
from app.models import Probe, ProbeDeployment, Task
from app.services import probe_lifecycle


@pytest.fixture(autouse=True)
def _deployment_key(monkeypatch):
    """Every case needs a usable credential key to store/reveal the secret."""
    monkeypatch.setattr(settings, "deployment_secret_key",
                        base64.b64encode(b"0" * 32).decode("ascii"))


def _probe(db, name: str, host: str = "10.0.0.9") -> Probe:
    probe = Probe(name=name, hostname=name, ip_address=host)
    db.add(probe)
    db.flush()
    return probe


def _task(db, probe_id: int, *, status: str = "Success", kind: str = "data_asset_scan") -> Task:
    task = Task(kind=kind, status=status, payload={"probe_id": probe_id})
    db.add(task)
    db.commit()
    return task


def _install(db, probe_id: int, *, retain: bool, host: str = "10.0.0.9") -> ProbeDeployment:
    # ONLINE, not a "SUCCEEDED" that no code writes: an install ends at ONLINE
    # once the probe's first heartbeat lands.
    deployment = ProbeDeployment(name=f"install-{probe_id}", action="install", host=host,
                                 port=22, username="root", auth_type="password", status="ONLINE",
                                 idempotency_key=f"install-{probe_id}", probe_id=probe_id,
                                 data_config={"retain_credential": retain})
    db.add(deployment)
    db.flush()
    store_credential(db, deployment, auth_type="password", password="pw")
    db.commit()
    return deployment


def test_a_hand_registered_probe_is_never_retired() -> None:
    with SessionLocal() as db:
        probe = _probe(db, "hand-registered")
        task = _task(db, probe.id)
        assert probe_lifecycle.retire_after_task(db, task) is None


def test_an_unfinished_task_never_retires_its_probe() -> None:
    with SessionLocal() as db:
        probe = _probe(db, "still-running")
        _install(db, probe.id, retain=True)
        task = _task(db, probe.id, status="Running")
        assert probe_lifecycle.retire_after_task(db, task) is None


def test_another_unfinished_task_keeps_the_probe() -> None:
    with SessionLocal() as db:
        probe = _probe(db, "shared-probe")
        _install(db, probe.id, retain=True)
        task = _task(db, probe.id)
        _task(db, probe.id, status="Running")
        assert probe_lifecycle.retire_after_task(db, task) is None


def test_a_deployment_that_did_not_retain_its_credential_is_left_alone() -> None:
    with SessionLocal() as db:
        probe = _probe(db, "operator-probe")
        _install(db, probe.id, retain=False)
        task = _task(db, probe.id)
        assert probe_lifecycle.retire_after_task(db, task) is None


def test_a_finished_task_retires_its_task_dedicated_probe(monkeypatch) -> None:
    dispatched: list[int] = []
    monkeypatch.setattr(probe_lifecycle, "dispatch_probe_deployment", dispatched.append)
    with SessionLocal() as db:
        probe = _probe(db, "task-dedicated")
        _install(db, probe.id, retain=True)
        task = _task(db, probe.id)
        removal_id = probe_lifecycle.retire_after_task(db, task)
        assert removal_id is not None
        removal = db.get(ProbeDeployment, removal_id)
        assert removal.action == "uninstall" and removal.probe_id == probe.id
        # The credential is moved to the removal row, ready to be destroyed when
        # that run ends; the probe account is left in place.
        assert removal.credential is not None
        assert removal.removal_options["remove_user"] is False
    assert dispatched == [removal_id]


def test_a_stopped_monitoring_task_retires_its_probe(monkeypatch) -> None:
    """The console's 监测任务 owns a task-dedicated probe just like a collection."""
    dispatched: list[int] = []
    monkeypatch.setattr(probe_lifecycle, "dispatch_probe_deployment", dispatched.append)
    with SessionLocal() as db:
        probe = _probe(db, "monitoring-owned", host="10.9.0.1")
        _install(db, probe.id, retain=True, host="10.9.0.1")
        task = _task(db, probe.id, kind="monitoring", status="Cancelled")
        removal_id = probe_lifecycle.retire_after_task(db, task)
        assert removal_id is not None
        assert db.get(ProbeDeployment, removal_id).action == "uninstall"
    assert dispatched == [removal_id]


def test_a_live_monitoring_task_keeps_its_probe() -> None:
    with SessionLocal() as db:
        probe = _probe(db, "monitoring-running", host="10.9.0.2")
        _install(db, probe.id, retain=True, host="10.9.0.2")
        task = _task(db, probe.id, kind="monitoring", status="Running")
        assert probe_lifecycle.retire_after_task(db, task) is None


def test_the_credential_a_console_removal_reuses_comes_from_the_install() -> None:
    with SessionLocal() as db:
        probe = _probe(db, "retained-credential", host="10.9.0.3")
        _install(db, probe.id, retain=True, host="10.9.0.3")
        assert probe_lifecycle.retained_credential(db, probe.id) == {
            "password": "pw", "private_key": None, "key_passphrase": None}
        # An install that did not keep the secret still needs one from the caller.
        other = _probe(db, "no-retained-credential", host="10.9.0.4")
        _install(db, other.id, retain=False, host="10.9.0.4")
        assert probe_lifecycle.retained_credential(db, other.id) is None


def test_deleting_a_probe_reuses_the_retained_credential(monkeypatch) -> None:
    """One click from the console: no SSH secret is typed again."""
    from fastapi.testclient import TestClient

    from app.api import probes as probes_api
    from app.main import app

    queued: list[int] = []
    monkeypatch.setattr(probes_api, "dispatch_probe_deployment", queued.append)
    with TestClient(app) as client:
        with SessionLocal() as db:
            probe = _probe(db, "console-removal", host="10.9.0.5")
            _install(db, probe.id, retain=True, host="10.9.0.5")
            probe_id = probe.id
        # httpx's TestClient.delete has no body kwarg, and the route reads one.
        response = client.request("DELETE", f"/api/v1/probes/{probe_id}",
                                  json={"remove_remote": True})
        assert response.status_code == 200, response.text
        body = response.json()
    assert body["action"] == "uninstall"
    assert queued == [body["deployment_id"]]
    with SessionLocal() as db:
        removal = db.get(ProbeDeployment, body["deployment_id"])
        assert removal.credential is not None


def test_deleting_a_probe_without_any_credential_says_so() -> None:
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        with SessionLocal() as db:
            probe = _probe(db, "hand-registered-removal", host="10.9.0.6")
            # No install behind it: nothing retained a credential to reuse.
            db.commit()
            probe_id = probe.id
        # httpx's TestClient.delete has no body kwarg, and the route reads one.
        response = client.request("DELETE", f"/api/v1/probes/{probe_id}",
                                  json={"remove_remote": True})
        assert response.status_code == 400
        assert "凭据" in response.json()["detail"]
