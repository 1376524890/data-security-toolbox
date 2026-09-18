import hashlib

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api import v1
from app.core.config import settings
from app.core.database import SessionLocal
from app.main import app
from app.models import AnalysisResult, PacketRecord, PcapRecord, Task
from app.services import pcap_files
from app.services.protocol_service import parse_pcap
from tests.test_dlp_detection_quality import capture


@pytest.fixture
def storage(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'storage_dir', tmp_path / 'storage')
    return tmp_path


def http_capture(path, body, content_type=b'text/plain'):
    return capture(path, [('10.0.0.2', 80, '10.0.0.1', 50000,
                          b'HTTP/1.1 200 OK\r\nContent-Type: ' + content_type
                          + b'\r\nContent-Disposition: attachment; filename="report.txt"'
                          + b'\r\nContent-Length: ' + str(len(body)).encode()
                          + b'\r\n\r\n' + body)])


def test_retains_non_sensitive_files_with_exact_bytes_and_bounded_preview(storage):
    body = b'ordinary report\n' * 4000
    path = http_capture(storage / 'download.pcap', body)
    result = pcap_files.extract_capture_files(path, 100, {'http': 1})
    item = next(i for i in result['items'] if i['sha256'] == hashlib.sha256(body).hexdigest())
    assert item['complete'] is True
    assert item['filename'] == 'report.txt'
    saved = pcap_files.object_path(100, item['id'])
    assert saved.read_bytes() == body
    chunk = pcap_files.preview(saved, 16, 32)
    assert bytes.fromhex(chunk['hex']) == body[16:48]
    assert chunk['text'] == body[16:48].decode()
    assert chunk['has_more'] is True


def test_multipart_upload_extracts_file_without_http_envelope(storage):
    body = b'file content\x00\xff'
    multipart = (b'--BOUND\r\nContent-Disposition: form-data; name="file"; filename="../../example.bin"'
                 b'\r\nContent-Type: application/octet-stream\r\n\r\n' + body + b'\r\n--BOUND--\r\n')
    path = capture(storage / 'upload.pcap', [('10.0.0.1', 51000, '10.0.0.2', 80,
                   b'POST /upload HTTP/1.1\r\nHost: example.test\r\n'
                   b'Content-Type: multipart/form-data; boundary=BOUND\r\nContent-Length: '
                   + str(len(multipart)).encode() + b'\r\n\r\n' + multipart)])
    result = pcap_files.extract_capture_files(path, 101, {})
    assert len(result['items']) == 1
    item = result['items'][0]
    assert item['filename'] == 'example.bin'
    assert pcap_files.object_path(101, item['id']).read_bytes() == body
    assert pcap_files.preview(pcap_files.object_path(101, item['id']), 0, 100)['binary']


def test_partial_http_is_marked_incomplete(storage):
    path = capture(storage / 'partial.pcap', [('10.0.0.2', 80, '10.0.0.1', 50000,
                   b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial')])
    item = pcap_files.extract_capture_files(path, 102, {})['items'][0]
    assert item['complete'] is False
    assert item['size'] == 7


def test_native_exporter_retains_response_without_python_reassembly(storage, monkeypatch):
    path = http_capture(storage / 'native.pcap', b'native object')
    monkeypatch.setattr(pcap_files, 'reassemble', lambda _: ([], {}))
    result = pcap_files.extract_capture_files(path, 103, {'http': 1})
    assert result['items']
    assert any(pcap_files.object_path(103, i['id']).read_bytes() == b'native object'
               for i in result['items'])


def test_invalid_upload_is_rejected_and_not_saved(storage, monkeypatch):
    monkeypatch.setattr(v1, '_dispatch', lambda *args: None)
    with TestClient(app) as client:
        result = client.post('/api/v1/pcaps/upload', files={'file': ('bad.pcap', b'not a capture')})
    assert result.status_code == 422
    assert not list((settings.storage_dir / 'pcaps').iterdir())


def test_manual_duplicate_returns_existing_capture_even_when_queue_busy(storage, monkeypatch):
    monkeypatch.setattr(v1, '_dispatch', lambda *args: None)
    data = http_capture(storage / 'duplicate.pcap', b'duplicate-upload-workbench').read_bytes()
    with TestClient(app) as client:
        first = client.post('/api/v1/pcaps/upload', files={'file': ('manual.pcap', data)})
        assert first.status_code == 200
        assert not first.json()['duplicate']
        def busy(_db):
            raise HTTPException(429, 'busy')
        monkeypatch.setattr(v1, '_queue_backpressure', busy)
        duplicate = client.post('/api/v1/pcaps/upload', files={'file': ('renamed.pcap', data)})
    assert duplicate.status_code == 200
    assert duplicate.json()['duplicate']
    assert duplicate.json()['id'] == first.json()['id']
    assert len(list((settings.storage_dir / 'pcaps').iterdir())) == 1


def test_file_preview_download_and_capture_scope(storage):
    path = http_capture(storage / 'scope.pcap', b'bounded preview body')
    with SessionLocal() as db:
        p = PcapRecord(filename='scope.pcap', storage_path=str(path), size=path.stat().st_size, sha256='scope')
        other = PcapRecord(filename='other.pcap', storage_path=str(path), size=path.stat().st_size, sha256='other')
        db.add_all([p, other])
        db.flush()
        result = pcap_files.extract_capture_files(path, p.id, {})
        task = Task(kind='pcap', status='Success', payload={'pcap_id': p.id})
        db.add(task)
        db.flush()
        db.add(AnalysisResult(task_id=task.id, module='pcap_files', content=result))
        db.commit()
        pid, other_id = p.id, other.id
    file_id = result['items'][0]['id']
    with TestClient(app) as client:
        listing = client.get(f'/api/v1/pcaps/{pid}/files').json()
        assert listing['items'][0]['binary_available']
        preview = client.get(f'/api/v1/pcaps/{pid}/files/{file_id}?offset=2&limit=7')
        assert preview.status_code == 200
        assert preview.json()['text'] == 'unded p'
        assert client.get(f'/api/v1/pcaps/{pid}/files/{file_id}/download').content == b'bounded preview body'
        assert client.get(f'/api/v1/pcaps/{other_id}/files/{file_id}').status_code == 404
        assert client.get(f'/api/v1/pcaps/{pid}/files/{file_id}?limit=999999').status_code == 422
        assert client.get(f'/api/v1/pcaps/{pid}/files/not-a-hash').status_code == 404


def test_packet_api_paginates_and_searches(storage):
    with SessionLocal() as db:
        p = PcapRecord(filename='pages.pcap', storage_path='unused', size=1, sha256='pages')
        db.add(p)
        db.flush()
        db.add_all([PacketRecord(pcap_id=p.id, number=i, timestamp=float(i),
                    src_ip='2001:db8::1', dst_ip='2001:db8::2', protocol='TCP',
                    length=100, info=f'packet {i}') for i in range(1, 152)])
        db.commit()
        pid = p.id
    with TestClient(app) as client:
        page = client.get(f'/api/v1/pcaps/{pid}/packets?page=2&page_size=100').json()
        assert page['total'] == 151
        assert len(page['items']) == 51
        assert page['items'][0]['number'] == 101
        filtered = client.get(f'/api/v1/pcaps/{pid}/packets?search=packet%20151').json()
        assert filtered['total'] == 1


def test_ipv6_packet_addresses_are_preserved(storage, monkeypatch):
    from app.services import protocol_service
    fields = ['1', '1234.25', '', '', '443', '60000', '', '', '100',
              'eth:ipv6:tcp', 'TCP', 'payload', '2001:db8::1', '2001:db8::2', '', '']
    monkeypatch.setattr(protocol_service, 'capinfos', lambda _: {})
    monkeypatch.setattr(protocol_service, 'stream_tshark', lambda *a, **k: iter(['\t'.join(fields)]))
    parsed = parse_pcap(storage / 'ipv6.pcap')
    assert parsed['packets'][0]['src_ip'] == '2001:db8::1'
    assert parsed['packets'][0]['dst_ip'] == '2001:db8::2'
