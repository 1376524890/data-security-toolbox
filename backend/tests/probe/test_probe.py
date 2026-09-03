from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))

import probe.probe as probe


def test_toml_config_demo(tmp_path: Path) -> None:
    path = tmp_path / "probe.toml"
    path.write_text("[agent]\ndemo = true\n", encoding="utf-8")
    config = probe.Config(path)
    assert config.capture["segment_seconds"] == 15
    assert config.agent["heartbeat_seconds"] == 5


def test_backoff_sequence() -> None:
    assert probe.backoff_seconds(1, 60) == 2
    assert probe.backoff_seconds(4, 60) == 30
    assert probe.backoff_seconds(99, 60) <= 60


def test_capture_command_prefers_dumpcap(monkeypatch) -> None:
    monkeypatch.setattr(probe.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "dumpcap" else "")
    config = probe.Config(Path("/tmp/nonexistent.toml"))
    command = probe.capture_command(config, Path("/tmp/out.pcapng.partial"))
    assert command[0].endswith("dumpcap")


def test_detect_configured_services_requires_zero(monkeypatch) -> None:
    class FakeSock:
        def __init__(self, *args):
            pass

        def settimeout(self, value):
            return None

        def connect_ex(self, target):
            return 0 if target[1] == 80 else 1

        def close(self):
            return None

    monkeypatch.setattr(probe.socket, "socket", FakeSock)
    services = probe.detect_configured_services([80, 443], "10.0.0.1")
    assert len(services) == 1
    assert services[0]["port"] == 80
