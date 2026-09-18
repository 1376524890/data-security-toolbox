import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.engine import registry
from app.engine.core.context import DetectionContext
from app.main import app
from app.rules import library, sync
from app.rules.sigma import SigmaRule, evaluate_sigma, supported_document


def sigma_rule():
    return SigmaRule('unit', 'Unit rule', 'High', .9, {
        'selection_a': {'CommandLine|contains': ['base64 ', 'curl ']},
        'selection_b': {'CommandLine|endswith': '| sh'},
        'filter': {'User': 'root'},
    }, 'all of selection_* and not filter')


def test_sigma_matches_one_record_and_honors_modifiers():
    rule = sigma_rule()
    assert evaluate_sigma(rule, [json.dumps({'CommandLine': 'base64 payload | sh', 'User': 'www'})])
    assert not evaluate_sigma(rule, [json.dumps({'CommandLine': 'base64 payload | sh', 'User': 'root'})])
    assert not evaluate_sigma(rule, [json.dumps({'CommandLine': 'base64 payload'}),
                                     json.dumps({'CommandLine': '| sh'})])
    assert not evaluate_sigma(rule, ['base64 payload | sh'])


def test_sigma_rejects_unsupported_semantics():
    assert not supported_document({'title': 'Unsupported', 'detection': {
        'selection': {'Field|base64offset': 'secret'}, 'condition': 'selection'}})
    assert not supported_document({'title': 'Unsupported', 'detection': {
        'selection': ['failed'], 'condition': 'selection | count() > 10'}})


def test_sigma_requires_matching_logsource():
    rule = sigma_rule()
    rule.logsource = {'product': 'linux', 'category': 'process_creation'}
    record = {'CommandLine': 'base64 payload | sh', 'User': 'www'}
    assert not evaluate_sigma(rule, [json.dumps(record)])
    record['_logsource'] = dict(rule.logsource)
    assert evaluate_sigma(rule, [json.dumps(record)])


def test_zeek_json_logs_keep_their_event_type(tmp_path):
    from app.integrations.zeek.parser import parse_zeek_dir
    from app.integrations.zeek.adapter import ZeekAdapter

    (tmp_path / 'notice.log').write_text(json.dumps({
        'note': 'DST::Sensitive_URI', 'msg': 'Credential parameter in HTTP URI'}))
    records = parse_zeek_dir(tmp_path)
    assert records[0]['event_type'] == 'notice'
    result = ZeekAdapter().adapt(records)
    assert result.findings[0].rule_id == 'ZEEK_DST_Sensitive_URI'


@pytest.mark.parametrize('engine', ['zeek', 'suricata'])
def test_native_runner_arguments_and_failure_are_not_silent(tmp_path, monkeypatch, engine):
    import importlib
    from types import SimpleNamespace

    runner = importlib.import_module(f'app.integrations.{engine}.runner')
    calls = []
    monkeypatch.setattr(runner.shutil, 'which', lambda _: '/usr/bin/' + engine)

    def failed(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1, stderr=b'broken configuration')

    monkeypatch.setattr(runner.subprocess, 'run', failed)
    with pytest.raises(RuntimeError, match='broken configuration'):
        getattr(runner, 'run_' + engine)(tmp_path / 'capture.pcap', tmp_path / 'output')
    if engine == 'suricata':
        assert '-q' not in calls[0]
        assert '-r' in calls[0] and '-S' in calls[0]
    else:
        assert 'redef LogAscii::use_json = T;' in calls[0]


def test_suricata_sll2_translation_preserves_payload_and_timestamp(tmp_path):
    import dpkt
    from decimal import Decimal
    from app.integrations.suricata.runner import compatible_capture

    original = tmp_path / 'original.pcap'
    packet = dpkt.sll2.SLL2(type=4, hrd=1, hlen=6, hdr=b'12345678', ethtype=0x0800)
    payload = b'captured payload bytes'
    with original.open('wb') as handle:
        writer = dpkt.pcap.Writer(handle, linktype=dpkt.pcap.DLT_LINUX_SLL2, nano=True)
        writer.writepkt(packet.pack_hdr() + payload, ts=Decimal('1234.123456789'))
    before = original.read_bytes()
    converted = compatible_capture(original, tmp_path)
    assert original.read_bytes() == before
    with converted.open('rb') as handle:
        reader = dpkt.pcap.Reader(handle)
        assert reader.datalink() == dpkt.pcap.DLT_LINUX_SLL
        timestamp, raw = next(iter(reader))
        assert timestamp == Decimal('1234.123456789')
        assert raw[16:] == payload
        assert dpkt.sll.SLL(raw).type == 4


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as data:
        for name, content in files.items():
            data.writestr(name, content)
    return output.getvalue()


def test_update_is_atomic_idempotent_and_removes_stale_files(tmp_path, monkeypatch):
    monkeypatch.setattr(library.settings, 'integration_dir', tmp_path)
    valid = 'title: Valid\nid: unit\ndetection:\n  selection: [failed]\n  condition: selection\n'
    monkeypatch.setattr(sync, '_download', lambda _: archive({'repo/rules/a.yml': valid}))
    assert sync.refresh('sigma_log_engine').status == 'updated'
    first = (tmp_path / 'sigma_rules' / 'active.json').read_text()
    monkeypatch.setattr(sync, '_download', lambda _: archive({'repo/rules/b.yml': valid}))
    assert sync.refresh('sigma_log_engine').status == 'updated'
    paths = library.rule_files('sigma_log_engine')
    assert sum(p.name == 'b.yml' for p in paths) == 1
    assert not any(p.name == 'a.yml' for p in paths)
    assert (tmp_path / 'sigma_rules' / 'active.json').read_text() != first
    current = (tmp_path / 'sigma_rules' / 'active.json').read_text()
    monkeypatch.setattr(sync, '_download', lambda _: archive({'repo/rules/b.yml': 'not yaml rule'}))
    assert sync.refresh('sigma_log_engine').status == 'failed'
    assert (tmp_path / 'sigma_rules' / 'active.json').read_text() == current


def test_archive_rejects_traversal_and_size_before_read(tmp_path, monkeypatch):
    monkeypatch.setattr(library.settings, 'integration_dir', tmp_path)
    monkeypatch.setattr(sync, '_download', lambda _: archive({'repo/rules/../../x.yml': 'x'}))
    assert sync.refresh('sigma_log_engine').status == 'failed'
    monkeypatch.setattr(sync, 'MAX_MEMBER_BYTES', 2)
    monkeypatch.setattr(sync, '_download', lambda _: archive({'repo/rules/x.yml': 'large'}))
    assert sync.refresh('sigma_log_engine').status == 'failed'
    assert not (tmp_path / 'sigma_rules' / 'active.json').exists()


def test_all_registered_engines_have_real_rule_inventory():
    with TestClient(app) as client:
        engines = client.get('/api/v1/engine/registry').json()
        items = client.get('/api/v1/rules', params={'include_content': False}).json()['items']
        for engine in engines:
            own = [item for item in items if item['engine'] == engine['name']]
            assert own, engine['name']
            assert engine['rule_count'] == len(own)
            assert engine['active_rule_files'] == sum(item['execution'] == 'active' for item in own)
        item = next(item for item in items if item['type'] == 'builtin')
        response = client.get('/api/v1/rules/content', params={'engine': item['engine'], 'path': item['path']})
        assert response.status_code == 200
        assert response.json()['content']
        assert client.get('/api/v1/rules/content', params={'engine': 'zeek', 'path': '/etc/passwd'}).status_code == 404


def test_registry_respects_disabled_rule_and_captures_definition(monkeypatch):
    context = DetectionContext(target_type='asset', assets=[{'service': 'telnet'}])
    findings = registry.run(context, names=['compliance_engine'])
    finding = next(item for item in findings if item.rule_id == 'COMP_WEAK_PROTOCOL_001')
    assert finding.evidence['rule_snapshot']['rule_id'] == finding.rule_id
    assert finding.evidence['rule_snapshot']['sha256']
    monkeypatch.setattr(library, 'rule_enabled', lambda *args: False)
    assert not registry.run(context, names=['compliance_engine'])


def test_alert_uses_historical_snapshot_and_current_dlp_policy():
    from app.api.v1 import _rule_definition
    from app.models import SystemSetting
    from sqlalchemy import select

    with SessionLocal() as db:
        snapshot = {'rule_id': 'PROTO_HTTP_UA_001', 'engine': 'protocol_engine',
                    'title': 'Historical rule', 'condition': 'old condition'}
        assert _rule_definition(db, snapshot['rule_id'], snapshot['engine'],
                                {'rule_snapshot': snapshot})['condition'] == 'old condition'
        row = db.scalar(select(SystemSetting).where(SystemSetting.key == 'dlp_policy'))
        if row is None:
            row = SystemSetting(key='dlp_policy', value={})
            db.add(row)
        row.value = {'min_matches': 7, 'min_confidence': .95}
        db.flush()
        result = _rule_definition(db, 'DLP_TRANSFER_001', 'dlp_engine')
        assert '>= 7' in result['condition'] and '0.95' in result['condition']
        db.rollback()


def test_suricata_prefixed_id_resolves_exact_sid(tmp_path, monkeypatch):
    from app.api.v1 import _rule_definition

    monkeypatch.setattr(library.settings, 'integration_dir', tmp_path)
    directory = tmp_path / 'suricata_rules'
    directory.mkdir()
    (directory / 'local.rules').write_text(
        'alert tcp any any -> any any (msg:"Exact signature"; sid:990001; rev:1;)\n'
        'alert tcp any any -> any any (msg:"Other signature"; sid:9900012; rev:1;)\n')
    with SessionLocal() as db:
        result = _rule_definition(db, 'SURICATA_990001', 'suricata')
        assert result['title'] == 'Exact signature'
        assert 'Other signature' not in result['content']


@pytest.mark.parametrize('value', ['bad', None, -1, float('inf')])
def test_invalid_rule_threshold_uses_default(monkeypatch, value):
    monkeypatch.setattr(library, 'rule_entry', lambda *args: {'params': {'limit': value}})
    assert library.rule_params('protocol_engine', 'unit', {'limit': 20})['limit'] == 20
