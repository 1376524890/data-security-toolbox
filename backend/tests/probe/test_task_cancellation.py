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


def _ruleset_client(tmp_path):
    """A real client with no network: it falls back to the in-package pack."""
    client = probe.RuleSetClient(directory=tmp_path / 'rules', fetch_json=lambda url: {},
                                 fetch_bytes=lambda url, limit: b'', manifest_url=lambda current: '',
                                 download_url=lambda version: '', agent_version='test')
    client.load_usable()
    return client


def test_empty_remote_paths_use_local_configuration(tmp_path, monkeypatch):
    agent = object.__new__(probe.ProbeAgent)
    agent.stop_event = threading.Event()
    agent.config = SimpleNamespace(data_assets={'paths': ['/srv/data']})
    # A data-asset job now pins the rule snapshot for the whole task.
    agent.ruleset = _ruleset_client(tmp_path)
    configs = []
    # `on_progress` was added in 3.4.0; the stub keeps the old two-argument
    # shape working so the assertion below still tests the merge, not progress.
    def discover(config, stop, on_progress=None):
        configs.append(config)
        return {'assets': [], 'complete': True}
    monkeypatch.setattr(probe, 'discover_data_assets', discover)
    agent._run_data_asset_job(tmp_path, {'paths': []}, None)
    assert configs[0]['paths'] == ['/srv/data']
    assert json.loads((tmp_path / 'data-assets.pending.json').read_text())['report_id']
