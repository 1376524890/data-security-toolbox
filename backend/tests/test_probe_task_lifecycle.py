from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app
from app.models import DataAsset, Task


def register(client, name):
    body = client.post('/api/v1/probes/register', json={'name': name, 'hostname': name, 'ip_address': '10.0.0.7'}).json()
    return body['id'], {'X-Probe-ID': str(body['id']), 'X-Probe-Token': body['token']}


def test_stop_delete_prevents_delivery_and_unblocks_probe_delete():
    with TestClient(app) as client:
        probe, headers = register(client, 'lifecycle-pending')
        task = client.post(f'/api/v1/probes/{probe}/data-assets/jobs', json={'paths': ['/srv']}).json()['id']
        assert client.delete(f'/api/v1/tasks/{task}').status_code == 409
        assert client.post(f'/api/v1/tasks/{task}/stop').json()['status'] == 'Cancelled'
        assert client.get(f'/api/v1/probes/{probe}/commands', headers=headers).json()['commands'] == []
        assert client.delete(f'/api/v1/tasks/{task}').status_code == 200
        assert client.get(f'/api/v1/tasks/{task}').status_code == 404
        assert task not in [item['id'] for item in client.get('/api/v1/tasks').json()['items']]
        assert client.get(f'/api/v1/probes/{probe}/tasks').json() == []
        assert client.delete(f'/api/v1/probes/{probe}').status_code == 200


def test_running_stop_and_deleted_task_ignore_late_reports():
    with TestClient(app) as client:
        probe, headers = register(client, 'lifecycle-running')
        task = client.post(f'/api/v1/probes/{probe}/data-assets/jobs', json={'paths': ['/srv']}).json()['id']
        assert client.get(f'/api/v1/probes/{probe}/commands', headers=headers).json()['commands'][0]['id'] == task
        assert client.get(f'/api/v1/probes/{probe}/command-status?task_id={task}', headers=headers).json()['stop'] is False
        client.post(f'/api/v1/tasks/{task}/stop')
        assert client.get(f'/api/v1/probes/{probe}/command-status?task_id={task}', headers=headers).json()['stop'] is True
        client.delete(f'/api/v1/tasks/{task}')
        report = {'task_id': task, 'report_id': 'late-result', 'assets': [{'name': 'late.csv', 'path': '/srv/late.csv'}]}
        assert client.post(f'/api/v1/probes/{probe}/data-assets', json=report, headers=headers).json()['duplicate'] is True
        with SessionLocal() as db:
            assert db.get(Task, task).status == 'Cancelled'
            assert not db.scalar(select(DataAsset).where(DataAsset.extra['probe_id'].as_integer() == probe))


def test_timeout_is_terminal_and_not_redelivered():
    with TestClient(app) as client:
        probe, headers = register(client, 'lifecycle-timeout')
        with SessionLocal() as db:
            old = datetime.now(UTC) - timedelta(hours=1)
            tasks = [Task(kind='probe_scan', status=status, created_at=old, started_at=old,
                          payload={'probe_id': probe, 'config': {'timeout_seconds': 5}}) for status in ['Pending', 'Running']]
            db.add_all(tasks)
            db.commit()
            ids = [task.id for task in tasks]
        assert client.get(f'/api/v1/probes/{probe}/commands', headers=headers).json()['commands'] == []
        with SessionLocal() as db:
            assert all(db.get(Task, task).status == 'Failed' for task in ids)


def test_inventory_identity_and_scope_use_full_path():
    with TestClient(app) as client:
        probe, headers = register(client, 'inventory-paths')
        def report(rid, paths, assets):
            return client.post(f'/api/v1/probes/{probe}/data-assets', headers=headers, json={
                'report_id': rid, 'scanned_paths': paths, 'max_depth': 0,
                'assets': [{'name': 'users.csv', 'path': path, 'asset_type': 'table'} for path in assets],
            })
        assert report('paths-first', ['/a', '/b'], ['/a/users.csv', '/b/users.csv', '/a/deep/users.csv']).status_code == 200
        assert report('paths-second', ['/a'], []).status_code == 200
        with SessionLocal() as db:
            rows = db.scalars(select(DataAsset).where(DataAsset.extra['probe_id'].as_integer() == probe)).all()
            states = {row.extra['path']: row.extra['status'] for row in rows}
            assert states == {'/a/users.csv': 'not_observed', '/b/users.csv': 'observed', '/a/deep/users.csv': 'observed'}


def test_old_probe_fails_before_queueing_data_collection():
    with TestClient(app) as client:
        body = client.post('/api/v1/probes/register', json={
            'name': 'old-inventory-probe', 'hostname': 'old', 'ip_address': '10.0.0.9',
            'metadata': {'agent_version': '3.2.1'},
        }).json()
        response = client.post(f'/api/v1/probes/{body["id"]}/data-assets/jobs', json={'paths': ['/srv']})
        assert response.status_code == 409
        assert '升级' in response.json()['detail']
        assert client.get(f'/api/v1/probes/{body["id"]}/tasks').json() == []
