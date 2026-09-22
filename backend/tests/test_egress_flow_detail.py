"""The egress report has to name the flow and say what was sensitive in it.

"Data left this IP" is not actionable on its own: the operator needs the
concrete flow (to open it packet by packet) and the rules the content matched.
"""
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models import AnalysisResult, Task

DST = '203.0.113.44'


def _seed_transfer(db) -> int:
    task = Task(kind='pcap', status='Success', payload={'pcap_id': 4242})
    db.add(task)
    db.flush()
    db.add(AnalysisResult(task_id=task.id, module='dlp', content={'coverage': {}, 'objects': [{
        'id': 1, 'sha256': 'e' * 64, 'filename': 'report.bin', 'size': 2048,
        'complete': True, 'content_type': 'text/plain', 'binary_available': True,
        'src_ip': '10.0.0.7', 'src_port': 51234, 'dst_ip': DST, 'dst_port': 443,
        'matches': [{'kind': 'id_card', 'count': 3, 'sensitive': True, 'confidence': 0.9,
                     'rule_id': 'DLP_ID_001', 'matches': [{'value': '11010119900307xxxx',
                                                           'context': '…姓名 张三 身份证 …'}]}],
    }]}))
    db.commit()
    return task.id


def test_the_egress_row_carries_the_flow_the_capture_and_the_rule_hits():
    with SessionLocal() as db:
        task_id = _seed_transfer(db)
    with TestClient(app) as client:
        body = client.get('/api/v1/assessments/egress').json()
    row = next(item for item in body['sections']['transfers']
               if item['task_id'] == task_id and item['object_id'] == 1)
    # The flow, so the row can be opened in the capture viewer.
    assert (row['pcap_id'], row['src_ip'], row['src_port'], row['dst_ip'], row['dst_port']) \
        == (4242, '10.0.0.7', 51234, DST, 443)
    # What was sensitive, and under which rule.
    assert row['sensitive'] is True
    assert row['rule_ids'] == ['DLP_ID_001']
    assert row['hit_count'] == 3
    assert row['matches'][0]['samples'][0]['value'] == '11010119900307xxxx'
    assert body['sections']['rules'] == [{'rule_id': 'DLP_ID_001', 'objects': 1}]
    assert any(kpi['key'] == 'sensitive' and kpi['value'] >= 1 for kpi in body['kpis'])
