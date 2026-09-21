import hashlib
import importlib.util
import json
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.json_storage import dumps_json
from app.main import app
from app.models import AnalysisResult, LocalCve, Task
from app.services import dlp_service, scan_service
from app.services.dlp import capture


def test_legacy_json_repair_preserves_records_and_literal_escapes(tmp_path):
    path = Path(__file__).parents[1] / 'alembic/versions/0013_safe_json_evidence.py'
    spec = importlib.util.spec_from_file_location('repair', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engine = sa.create_engine('sqlite://')
    metadata = sa.MetaData()
    table = sa.Table('evidence', metadata, sa.Column('id', sa.Integer, primary_key=True), sa.Column('value', sa.JSON))
    metadata.create_all(engine)
    original = {'banner': 'I' + chr(0) + 'D', 'literal': r'\u0000', 'nested': [chr(0)]}
    with engine.begin() as connection:
        connection.execute(table.insert().values(id=1, value=original))
        module.op = Operations(MigrationContext.configure(connection))
        module.upgrade()
        module.upgrade()
        repaired = connection.scalar(sa.select(table.c.value))
        assert repaired == {'banner': r'I\x00D', 'literal': r'\u0000', 'nested': [r'\x00']}
        assert json.loads(dumps_json(original)) == repaired


def test_cves_paginate_and_keep_legacy_contract():
    with SessionLocal() as db:
        for i in range(105):
            db.add(LocalCve(cve_id=f'CVE-2098-{90000+i}', cvss_score=5, description={'text': 'fixture'}))
        db.commit()
    with TestClient(app) as client:
        first = client.get('/api/v1/offline/cves', params={'search':'CVE-2098-', 'page':1, 'page_size':50}).json()
        third = client.get('/api/v1/offline/cves', params={'search':'CVE-2098-', 'page':3, 'page_size':50}).json()
        assert first['total'] == 105 and len(first['items']) == 50 and len(third['items']) == 5
        assert not {x['cve_id'] for x in first['items']} & {x['cve_id'] for x in third['items']}
        assert isinstance(client.get('/api/v1/offline/cves').json(), list)
        assert client.get('/api/v1/offline/cves?page=0').status_code == 422


def test_sensitive_transfer_bytes_and_hash_match_download(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'storage_dir', tmp_path)
    body = b'company-secret' + bytes(range(256)) * 20
    # The capture primitives are looked up in their own module; the DLP service
    # only re-exports them for callers that still import the old path.
    monkeypatch.setattr(capture, 'reassemble', lambda path: ([(('10.8.0.1',12345,'10.8.0.2',80), b'http', False)], {}))
    monkeypatch.setattr(capture, 'http_objects', lambda data: [{'filename':'sample.bin','body':body,'complete':True}])
    result, _, findings = dlp_service.analyze_capture(tmp_path / 'test.pcap', {'keywords':['company-secret']})
    obj = result['objects'][0]
    assert obj['sha256'] == hashlib.sha256(body).hexdigest() and obj['binary_available']
    assert 'hex' not in findings[0]['evidence']
    with SessionLocal() as db:
        task = Task(kind='pcap', status='Success', payload={'pcap_id':123})
        db.add(task); db.flush()
        task_id = task.id
        db.add(AnalysisResult(task_id=task_id, module='dlp', content=result)); db.commit()
    with TestClient(app) as client:
        url = f'/api/v1/dlp/transfers/{task_id}/1/content'
        preview = client.get(url).json()
        assert bytes.fromhex(preview['hex']) == body[:4096] and preview['truncated']
        response = client.get(url + '?download=true')
        assert response.content == body and response.headers['content-type'] == 'application/octet-stream'
        assert client.get(f'/api/v1/dlp/transfers/{task_id}/999/content').status_code == 404


def test_builtin_rule_packs_are_listed_and_yara_executes(tmp_path):
    from app.engine.data_engine.engine import yara_scan
    with TestClient(app) as client:
        rules = client.get('/api/v1/rules').json()['items']
        assert any(item['type'] == 'suricata' and item['name'] == 'dst_sensitive.rules' for item in rules)
        assert any(item['type'] == 'yara' and item['name'] == 'sensitive_files.yar' for item in rules)
    file = tmp_path / 'key.txt'
    file.write_text('-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----')
    rule_dir = Path(__file__).parents[1] / 'app/rules/data'
    assert any(hit['rule'] == 'DST_Private_Key_Material' for hit in yara_scan(file, rule_dir))
    file.write_text('ordinary file')
    assert not yara_scan(file, rule_dir)


def test_probe_scan_uses_default_200_ports():
    with TestClient(app) as client:
        probe = client.post('/api/v1/probes/register', json={'name':'top200-regression'}).json()
        result = client.post('/api/v1/scan', json={'target':'10.8.0.0/24', 'probe_id':probe['id']})
        assert result.status_code == 200
        with SessionLocal() as db:
            task = db.get(Task, result.json()['id'])
            assert len(task.payload['config']['ports']) == 200
            assert len(set(task.payload['config']['ports'])) == 200
    assert len(scan_service.expand_targets('10.0.0.0/8', max_hosts=4)) == 4
