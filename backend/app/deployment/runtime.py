"""Run preflight with the exact offline runtime that will be installed."""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.deployment.package import PackageError, find_package
from app.deployment.ssh_client import SshClient


def check_runtime(ssh: SshClient, arch: str, backend_url: str) -> dict[str, Any]:
    package = find_package(arch)
    metadata = package['manifest'].get('runtime', {})
    if not metadata.get('self_contained'):
        raise PackageError('probe package does not include a self-contained runtime')
    rc, output, _ = ssh.exec('mktemp -d /tmp/dstprobe-runtime-XXXXXXXX')
    remote = output.strip()
    if rc or not re.fullmatch(r'/tmp/dstprobe-runtime-[A-Za-z0-9]+', remote):
        raise PackageError('cannot create runtime preflight directory')
    try:
        ssh.sftp_put(package['dir'] / 'runtime.tar.gz', f'{remote}/runtime.tar.gz')
        ssh.sftp_put(package['dir'] / 'runtime_check.py', f'{remote}/runtime_check.py')
        rc, output, _ = ssh.exec(f'sha256sum {remote}/runtime.tar.gz')
        if rc or not output.strip().startswith(metadata['sha256'] + ' '):
            raise PackageError('uploaded runtime digest mismatch')
        rc, _, _ = ssh.exec(f'tar -xzf {remote}/runtime.tar.gz -C {remote}', timeout=120)
        if rc:
            raise PackageError('cannot extract runtime preflight archive')
        ca_argument = ''
        if settings.deployment_ca_file:
            source = Path(settings.deployment_ca_file)
            if not source.is_file():
                raise PackageError('configured deployment CA file is missing')
            ssh.sftp_put(source, f'{remote}/ca.pem')
            ca_argument = f' --ca {remote}/ca.pem'
        _, output, _ = ssh.exec(
            f'{remote}/runtime/bin/python -s {remote}/runtime_check.py '
            f'--runtime {remote}/runtime --backend-url {shlex.quote(backend_url)}{ca_argument}',
            timeout=90,
        )
        try:
            result = json.loads(output)
        except (ValueError, TypeError) as exc:
            raise PackageError(
                'bundled runtime cannot execute on target (CPU/kernel/noexec)'
            ) from exc
        if not isinstance(result, dict):
            raise PackageError('invalid runtime self-check response')
        return result
    finally:
        ssh.exec(f'rm -rf -- {remote}')
