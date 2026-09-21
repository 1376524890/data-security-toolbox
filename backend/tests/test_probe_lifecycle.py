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


def _probe(db, name: str) -> Probe:
    probe = Probe(name=name, hostname=name, ip_address="10.0.0.9")
    db.add(probe)
    db.flush()
    return probe


def _task(db, probe_id: int, *, status: str = "Success", kind: str = "data_asset_scan") -> Task:
    task = Task(kind=kind, status=status, payload={"probe_id": probe_id})
    db.add(task)
    db.commit()
    return task


def _install(db, probe_id: int, *, retain: bool) -> ProbeDeployment:
    deployment = ProbeDeployment(name=f"install-{probe_id}", action="install", host="10.0.0.9",
                                 port=22, username="root", auth_type="password", status="SUCCEEDED",
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
