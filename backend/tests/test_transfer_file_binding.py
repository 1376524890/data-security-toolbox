"""A sensitive transfer must name the file it carried, not just a risk point.

A captured network object is identified by the SHA256 of the bytes it carried.
When a scan has inventoried a file with the same digest, the two are the same
content, so the flow report can attach the transfer to that concrete file.
"""
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models import AnalysisResult, AssetInstance, DataObject, Task
from app.services.data_objects.queries import files_by_content_hash

DIGEST = 'a' * 64
OTHER = 'b' * 64
BOUND = 'd' * 64


def _instance(db, *, sha: str, path: str, status: str = 'ACTIVE', name: str = '') -> int:
    obj = DataObject(object_key=f'full:file:{sha}', object_type='file', hash_type='full',
                     content_hash=sha)
    db.add(obj)
    db.flush()
    instance = AssetInstance(object_id=obj.id, owner_key='file-source:1', path=path,
                             name=name or path.rsplit('/', 1)[-1], instance_type='file',
                             content_hash=sha, hash_type='full', status=status,
                             categories=['id_card'], sensitivity='High',
                             extra={'source_name': '共享目录', 'host': '10.0.0.7'})
    db.add(instance)
    db.flush()
    return instance.id


def _transfer(db, *, sha: str, object_id: int = 1) -> tuple[int, int]:
    task = Task(kind='pcap', status='Success', payload={'pcap_id': 900 + object_id})
    db.add(task)
    db.flush()
    db.add(AnalysisResult(task_id=task.id, module='dlp', content={'coverage': {},
          'objects': [{'id': object_id, 'sha256': sha, 'filename': 'upload.bin', 'size': 10,
                       'complete': True, 'src_ip': '10.0.0.7', 'dst_ip': '8.8.8.8',
                       'matches': [{'kind': 'id_card', 'count': 2}]}]}))
    db.commit()
    return task.id, object_id


def test_files_by_content_hash_matches_only_active_instances():
    with SessionLocal() as db:
        live = _instance(db, sha=DIGEST, path='/data/客户名单.xlsx')
        _instance(db, sha=OTHER, path='/data/其他.txt', status='NOT_OBSERVED')
        db.commit()
        found = files_by_content_hash(db, [DIGEST, OTHER, 'not-a-hash', '', None])
    assert list(found) == [DIGEST]
    assert found[DIGEST][0]['instance_id'] == live
    assert found[DIGEST][0]['path'] == '/data/客户名单.xlsx'
    assert found[DIGEST][0]['source_name'] == '共享目录'


def test_transfer_payload_binds_the_object_to_the_file():
    with SessionLocal() as db:
        _instance(db, sha=BOUND, path='/data/客户名单-副本.xlsx')
        task_id, object_id = _transfer(db, sha=BOUND)
    with TestClient(app) as client:
        body = client.get('/api/v1/dlp/transfers').json()
    row = next(item for item in body['items']
               if item['task_id'] == task_id and item['id'] == object_id)
    assert row['file_bound'] is True
    assert row['files'][0]['path'] == '/data/客户名单-副本.xlsx'
    assert body['file_bound_objects'] >= 1


def test_unmatched_transfer_says_so_instead_of_inventing_a_file():
    with SessionLocal() as db:
        task_id, object_id = _transfer(db, sha='c' * 64, object_id=2)
    with TestClient(app) as client:
        body = client.get('/api/v1/dlp/transfers').json()
    row = next(item for item in body['items']
               if item['task_id'] == task_id and item['id'] == object_id)
    assert row['file_bound'] is False
    assert row['files'] == []
