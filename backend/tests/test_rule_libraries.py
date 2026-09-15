import io
import json
import sqlite3
import tarfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.libraries import router
from app.core.config import settings
from app.core.database import get_db
from app.models import Base, LocalCve
from app.services.grype_library import extract_database, import_database, import_lock, score_from_blob
from app.services.rule_library import import_presidio_wheel, managed_rules, scan_managed


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from fastapi import FastAPI
    monkeypatch.setattr(settings, 'integration_dir', tmp_path / 'integrations')
    monkeypatch.setattr(settings, 'storage_dir', tmp_path / 'storage')
    settings.integration_dir.mkdir()
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = lambda: db
        with TestClient(app) as client:
            yield client, db
    engine.dispose()


def grype_fixture(path, records):
    with sqlite3.connect(path) as db:
        db.executescript('CREATE TABLE db_metadata(model INTEGER); INSERT INTO db_metadata VALUES (6); '
                         'CREATE TABLE vulnerability_handles(id INTEGER, name TEXT, published_date TEXT, modified_date TEXT, provider_id TEXT, blob_id INTEGER); '
                         'CREATE TABLE blobs(id INTEGER, value TEXT);')
        for index, record in enumerate(records):
            db.execute('INSERT INTO vulnerability_handles VALUES (?, ?, ?, ?, ?, ?)', (index, record['id'], '', '', record.get('provider', 'nvd'), index))
            db.execute('INSERT INTO blobs VALUES (?, ?)', (index, json.dumps(record)))
    return path


def test_manual_dlp_rule_is_used_and_can_be_disabled(environment):
    client, _ = environment
    response = client.post('/api/v1/dlp/rules', json={'name': 'Internal record', 'entity': 'INTERNAL', 'pattern': r'INTERNAL-\d{6}'})
    assert response.status_code == 200
    rule = response.json()
    hit = scan_managed('INTERNAL-123456', managed_rules())[0]
    assert hit['kind'] == 'INTERNAL' and '123456' not in str(hit)
    assert client.patch('/api/v1/dlp/rules/' + rule['id'], json={'enabled': False}).status_code == 200
    assert not scan_managed('INTERNAL-123456', managed_rules())
    assert client.post('/api/v1/dlp/rules', json={'name': 'bad', 'pattern': '('}).status_code == 422
    assert client.post('/api/v1/dlp/rules', json={'name': 'empty', 'pattern': '.*'}).status_code == 422


def test_presidio_import_does_not_execute_code_and_preserves_manual(environment):
    client, _ = environment
    client.post('/api/v1/dlp/rules', json={'name': 'local', 'pattern': 'local-secret'})
    source = '''
raise RuntimeError("upstream code must not execute")
class EmailRecognizer:
    PATTERNS = [Pattern("email", r"sample@[a-z]+[.]com", 0.8)]
    def __init__(self, supported_entity="EMAIL_ADDRESS"): pass
'''
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as wheel:
        wheel.writestr('presidio_analyzer/predefined_recognizers/generic/email_recognizer.py', source)
    assert import_presidio_wheel(buffer.getvalue(), 'test')['imported'] == 1
    rule = next(r for r in managed_rules() if r['source'] == 'Presidio')
    assert scan_managed('sample@example.com', managed_rules())
    client.patch('/api/v1/dlp/rules/' + rule['id'], json={'enabled': False})
    import_presidio_wheel(buffer.getvalue(), 'test2')
    assert len(managed_rules()) == 2
    assert not next(r for r in managed_rules() if r['source'] == 'Presidio')['enabled']


def test_yara_authoring_activates_real_file_scan(environment, tmp_path):
    from app.engine.data_engine.engine import yara_scan
    client, _ = environment
    response = client.post('/api/v1/rules', json={'rule_type': 'yara', 'name': 'company_secret',
        'content': 'rule company_secret { strings: $a = "INTERNAL-SECRET" condition: $a }'})
    assert response.status_code == 200
    path = tmp_path / 'sample.txt'
    path.write_text('INTERNAL-SECRET')
    assert yara_scan(path, tmp_path / 'empty')[0]['rule'] == 'company_secret'
    assert client.post('/api/v1/rules', json={'rule_type': 'yara', 'name': 'bad', 'content': 'invalid'}).status_code == 422
    assert client.post('/api/v1/rules', json={'rule_type': 'yara', 'name': '../escape', 'content': 'invalid'}).status_code == 422


def test_suricata_requires_every_line_and_sid(environment, monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, 'which', lambda name: None)
    client, _ = environment
    rule = 'alert tcp any any -> any any (msg:"Sensitive transfer"; content:"INTERNAL-SECRET"; sid:9900001; rev:1;)'
    assert client.post('/api/v1/rules', json={'rule_type': 'suricata', 'name': 'valid', 'content': rule}).status_code == 200
    response = client.post('/api/v1/rules', json={'rule_type': 'suricata', 'name': 'invalid', 'content': rule + '\nnot a rule'})
    assert response.status_code == 422
    assert len(list((settings.integration_dir / 'suricata_rules').glob('*.rules'))) == 1


def test_grype_import_updates_and_preserves_manual(environment, tmp_path):
    _, db = environment
    db.add(LocalCve(cve_id='CVE-2026-99999', source='manual', description={'text': 'manual'}))
    db.commit()
    records = [{'id': 'CVE-2026-12345', 'description': 'product vulnerability', 'severities': [{'value': {'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'}}]},
               {'id': 'CVE-2026-99999', 'description': 'upstream'}]
    path = grype_fixture(tmp_path / 'vulnerability.db', records)
    result = import_database(db, path)
    assert result['imported'] == 1 and result['preserved'] == 1
    row = db.scalar(select(LocalCve).where(LocalCve.cve_id == 'CVE-2026-12345'))
    assert row.cvss_score == 10 and row.severity == 'Critical'
    assert import_database(db, path)['updated'] == 1
    assert db.scalar(select(LocalCve).where(LocalCve.cve_id == 'CVE-2026-99999')).description['text'] == 'manual'


def test_invalid_grype_rolls_back(environment, tmp_path):
    _, db = environment
    path = grype_fixture(tmp_path / 'invalid.db', [{'id': 'CVE-2026-12345'}])
    with sqlite3.connect(path) as sqlite:
        sqlite.execute("UPDATE blobs SET value='broken json'")
    with pytest.raises(ValueError):
        import_database(db, path)
    assert db.scalar(select(LocalCve.id)) is None


def test_archive_traversal_rejected(tmp_path):
    archive = tmp_path / 'unsafe.tar'
    with tarfile.open(archive, 'w') as tar:
        item = tarfile.TarInfo('../vulnerability.db')
        item.size = 1
        tar.addfile(item, io.BytesIO(b'x'))
    with pytest.raises(ValueError):
        extract_database(archive, tmp_path)


def test_cvss_vector_and_import_lock(environment):
    assert score_from_blob({'severities': [{'value': {'vector': 'AV:N/AC:M/Au:N/C:C/I:C/A:C'}}]}) == 9.3
    with import_lock():
        with pytest.raises(ValueError):
            with import_lock():
                pass
    with import_lock():
        pass


def test_manual_cve_validation(environment):
    client, _ = environment
    payload = {'cve_id': 'CVE-2026-54321', 'description': 'Manual vulnerability', 'cvss_score': 8.1}
    assert client.post('/api/v1/offline/cves', json=payload).status_code == 200
    assert client.post('/api/v1/offline/cves', json=payload).status_code == 409
    assert client.post('/api/v1/offline/cves', json={**payload, 'cvss_score': 12}).status_code == 422


def test_all_interface_capture_runs_managed_dlp(environment, tmp_path):
    import dpkt
    import socket
    import struct
    from app.services.dlp_service import analyze_capture
    client, _ = environment
    client.post('/api/v1/dlp/rules', json={'name': 'company document', 'entity': 'COMPANY', 'pattern': 'INTERNAL-SECRET'})
    body = b'INTERNAL-SECRET'
    payload = b'POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 15\r\n\r\n' + body
    tcp = dpkt.tcp.TCP(sport=50000, dport=80, seq=1, flags=dpkt.tcp.TH_ACK, data=payload)
    ip = dpkt.ip.IP(src=socket.inet_aton('10.0.0.2'), dst=socket.inet_aton('10.0.0.3'), p=6, data=tcp)
    ip.len = len(ip)
    cooked_v2 = struct.pack('!HHIHBB8s', 0x0800, 0, 2, 1, 0, 6, b'\0'*8)
    path = tmp_path / 'all-nics.pcap'
    with path.open('wb') as output:
        writer = dpkt.pcap.Writer(output, linktype=276)
        writer.writepkt(cooked_v2 + bytes(ip), ts=1)
    result, _, findings = analyze_capture(path, {'categories': [], 'min_matches': 1})
    assert findings and findings[0]['evidence']['matches'][0]['kind'] == 'COMPANY'
    assert not result['coverage']['rule_timeouts']
    assert 'INTERNAL-SECRET' not in json.dumps(result)
