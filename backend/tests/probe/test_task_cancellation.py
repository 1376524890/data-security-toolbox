import io
import json
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parents[3]))
from probe import probe


def test_remote_stop_is_checked_and_cached(monkeypatch):
    agent = object.__new__(probe.ProbeAgent)
    agent.stop_event = threading.Event()
    agent.probe_id = 5
    agent.config = SimpleNamespace(base_url=lambda: 'http://localhost')
    agent.headers = lambda: {}
    calls = []
    monkeypatch.setattr(probe, 'ssl_context', lambda _: None)
    def urlopen(req, **kwargs):
        calls.append(req.full_url)
        return io.BytesIO(b'{"stop":true}')
    monkeypatch.setattr(probe.urllib.request, 'urlopen', urlopen)
    stop = agent._job_stop_event(12)
    assert stop.is_set() and stop.is_set()
    assert len(calls) == 1 and 'task_id=12' in calls[0]


def test_empty_remote_paths_use_local_configuration(tmp_path, monkeypatch):
    agent = object.__new__(probe.ProbeAgent)
    agent.stop_event = threading.Event()
    agent.config = SimpleNamespace(data_assets={'paths': ['/srv/data']})
    configs = []
    def discover(config, stop):
        configs.append(config)
        return {'assets': [], 'complete': True}
    monkeypatch.setattr(probe, 'discover_data_assets', discover)
    agent._run_data_asset_job(tmp_path, {'paths': []}, None)
    assert configs[0]['paths'] == ['/srv/data']
    assert json.loads((tmp_path / 'data-assets.pending.json').read_text())['report_id']
