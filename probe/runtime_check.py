"""Validate the shipped runtime without depending on a host Python installation."""
from __future__ import annotations

import argparse
import importlib
import json
import platform
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--backend-url', default='')
    parser.add_argument('--ca', default='')
    args = parser.parse_args()
    result = {'ok': False, 'python': platform.python_version(), 'connectivity': False}
    try:
        root = Path(args.runtime).resolve()
        metadata = json.loads((root / 'runtime.json').read_text())
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
        if metadata['arch'] != arch or sys.version_info[:2] != (3, 11):
            raise RuntimeError('runtime architecture or Python version mismatch')
        # Layout first: a truncated or partial runtime must never be activated.
        for name in ('bin/python', 'bin/dumpcap', 'bin/tcpdump', 'lib/ld.so',
                     'python/bin/python3.11', 'ca-certificates.crt'):
            if not (root / name).exists():
                raise RuntimeError('runtime is incomplete: missing ' + name)
        # A host interpreter reports a different base prefix. Refusing here keeps
        # the platform from deploying a package that would fall back to host
        # libraries without anyone noticing.
        if Path(sys.base_prefix).resolve() != (root / 'python').resolve():
            raise RuntimeError('not running the bundled interpreter')
        for name in ('tomllib', 'ssl', 'sqlite3', 'ctypes', 'psutil', 'regex',
                     'requests', 'openpyxl'):
            importlib.import_module(name)
        for name in ('dumpcap', 'tcpdump'):
            subprocess.run([str(root / 'bin' / name), '--version'], check=True,
                           capture_output=True, timeout=15)
        result.update(ok=True, capture_tool='dumpcap', arch=arch)
        if args.backend_url:
            context = ssl.create_default_context(cafile=args.ca or None)
            with urllib.request.urlopen(args.backend_url.rstrip('/') + '/api/v1/health',
                                        context=context, timeout=10) as response:
                result['connectivity'] = response.status == 200
    except Exception as exc:  # noqa: BLE001 - sanitize all remote self-check failures
        # Remote error text may contain credentials or URL query strings.
        result['error'] = type(exc).__name__
    print(json.dumps(result))
    return 0 if result['ok'] and (not args.backend_url or result['connectivity']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
