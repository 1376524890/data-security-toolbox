import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from app.deployment import preflight, runtime
from app.deployment.package import PackageError


def test_preflight_does_not_require_host_python_or_capture_tools(monkeypatch):
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        if 'os-release' in command:
            return 0, 'ID=ubuntu', ''
        if 'uname -m' in command:
            return 0, 'x86_64', ''
        if 'ps -p 1' in command:
            return 0, 'systemd', ''
        if 'free -m' in command:
            return 0, '4096', ''
        if 'df -P' in command:
            return 0, '10485760', ''
        if '/sys/class/net' in command:
            return 0, 'eth0\nlo', ''
        if 'sudo -n' in command:
            return 0, 'sudo-ok', ''
        raise AssertionError(command)

    ssh = Mock(username='root')
    ssh.exec.side_effect = execute
    check = Mock(return_value={'ok': True, 'python': '3.11.16', 'capture_tool': 'dumpcap',
                              'connectivity': True})
    monkeypatch.setattr(preflight, 'check_runtime', check)
    result = preflight.run_preflight(ssh, backend_url='http://platform:8000')
    assert result['compatible']
    check.assert_called_once_with(ssh, 'amd64', 'http://platform:8000')
    assert not any('python3' in command or 'command -v dumpcap' in command for command in commands)


@pytest.mark.parametrize('failure', ['digest', 'extract', 'execute', 'network', 'success'])
def test_runtime_upload_checks_digest_and_cleans_up(monkeypatch, failure):
    metadata = {'self_contained': True, 'sha256': 'a' * 64}
    monkeypatch.setattr(runtime, 'find_package', lambda arch: {
        'dir': Path('/packages'), 'manifest': {'runtime': metadata},
    })
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        if command.startswith('mktemp'):
            return 0, '/tmp/dstprobe-runtime-abcdefgh\n', ''
        if command.startswith('sha256sum'):
            digest = 'b' * 64 if failure == 'digest' else metadata['sha256']
            return 0, digest + '  runtime.tar.gz', ''
        if command.startswith('tar '):
            return (1 if failure == 'extract' else 0), '', ''
        if '/bin/python ' in command:
            if failure == 'execute':
                return 126, '', 'Exec format error'
            return 0, json.dumps({'ok': True, 'connectivity': failure != 'network'}), ''
        return 0, '', ''

    ssh = Mock()
    ssh.exec.side_effect = execute
    if failure in ('digest', 'extract', 'execute'):
        with pytest.raises(PackageError):
            runtime.check_runtime(ssh, 'amd64', 'http://platform:8000')
    else:
        result = runtime.check_runtime(ssh, 'amd64', 'http://platform:8000')
        assert result['connectivity'] == (failure == 'success')
    assert commands[-1] == 'rm -rf -- /tmp/dstprobe-runtime-abcdefgh'
    assert ssh.sftp_put.call_count == 2


def test_source_only_package_is_rejected_before_touching_target(monkeypatch):
    monkeypatch.setattr(runtime, 'find_package', lambda arch: {'manifest': {}})
    ssh = Mock()
    with pytest.raises(PackageError, match='self-contained'):
        runtime.check_runtime(ssh, 'amd64', 'http://platform:8000')
    ssh.exec.assert_not_called()


def test_unsafe_remote_temp_path_is_not_used_or_deleted(monkeypatch):
    monkeypatch.setattr(runtime, 'find_package', lambda arch: {
        'manifest': {'runtime': {'self_contained': True}},
    })
    ssh = Mock()
    ssh.exec.return_value = (0, '/tmp/other; touch /tmp/injected', '')
    with pytest.raises(PackageError, match='directory'):
        runtime.check_runtime(ssh, 'amd64', 'http://platform:8000')
    assert ssh.exec.call_count == 1
    ssh.sftp_put.assert_not_called()
