from fastapi.testclient import TestClient
from sqlalchemy import text
from datetime import UTC, datetime, timedelta

from app.core.config import settings
from app.core.database import SessionLocal
from app.main import app
from app.models import Asset, Probe, ProbeDeployment, ProbeEnrollment, Task


def test_delete_preserves_assets_and_rejects_old_credentials():
    with TestClient(app) as client:
        body = client.post('/api/v1/probes/register', json={
            'name': 'delete-history', 'hostname': 'host', 'ip_address': '10.0.0.8',
        }).json()
        probe_id = body['id']
        with SessionLocal() as db:
            db.execute(text('PRAGMA foreign_keys=ON'))
            asset = Asset(probe_id=probe_id, ip='10.0.0.8')
            db.add(asset)
            db.commit()
            asset_id = asset.id
        assert client.delete(f'/api/v1/probes/{probe_id}').status_code == 200
        with SessionLocal() as db:
            assert db.get(Probe, probe_id) is None
            assert db.get(Asset, asset_id).probe_id is None
        assert client.post(f'/api/v1/probes/{probe_id}/heartbeat', json={'status': 'online'},
                           headers={'X-Probe-ID': str(probe_id), 'X-Probe-Token': body['token']}).status_code in (401, 404)
        assert client.delete(f'/api/v1/probes/{probe_id}').status_code == 404


def test_delete_rejects_active_tasks():
    with TestClient(app) as client:
        with SessionLocal() as db:
            probe = Probe(name='delete-busy')
            db.add(probe)
            db.flush()
            probe_id = probe.id
            db.add(Task(kind='probe_scan', status='Pending', payload={'probe_id': probe_id}))
            db.commit()
        assert client.delete(f'/api/v1/probes/{probe_id}').status_code == 409
        with SessionLocal() as db:
            assert db.get(Probe, probe_id) is not None


def test_delete_requires_admin_session(monkeypatch):
    with TestClient(app) as client:
        monkeypatch.setattr(settings, 'app_env', 'production')
        assert client.delete('/api/v1/probes/123456').status_code == 401


def test_delete_checks_deployment_and_preserves_history():
    with TestClient(app) as client:
        with SessionLocal() as db:
            deployment = ProbeDeployment(name='delete-deployment', host='10.0.0.9',
                                         idempotency_key='delete-deployment', status='REGISTERED')
            db.add(deployment)
            db.flush()
            deployment_id = deployment.id
            probe = Probe(name='delete-deployed-probe', deployment_id=deployment_id)
            db.add(probe)
            db.flush()
            probe_id = probe.id
            deployment.probe_id = probe_id
            enrollment = ProbeEnrollment(deployment_id=deployment_id, probe_id=probe_id,
                                         token_hash='delete-enrollment', expires_at=datetime.now(UTC) + timedelta(hours=1))
            db.add(enrollment)
            db.commit()
            enrollment_id = enrollment.id
        assert client.delete(f'/api/v1/probes/{probe_id}').status_code == 409
        with SessionLocal() as db:
            db.get(ProbeDeployment, deployment_id).status = 'ONLINE'
            db.commit()
        assert client.delete(f'/api/v1/probes/{probe_id}').status_code == 200
        with SessionLocal() as db:
            assert db.get(ProbeDeployment, deployment_id).probe_id is None
            enrollment = db.get(ProbeEnrollment, enrollment_id)
            assert enrollment.probe_id is None
            assert enrollment.expires_at.replace(tzinfo=UTC) <= datetime.now(UTC)
