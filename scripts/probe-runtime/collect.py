"""Collect a private interpreter, capture binaries and their ELF library closure.

Executed inside the architecture-specific build container, never on a target.
The private loader is invoked explicitly, so the host's glibc is not used.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path('/out/runtime')
ROOT.mkdir(parents=True)
for name in ('bin', 'lib', 'python/bin', 'licenses'):
    (ROOT / name).mkdir(parents=True, exist_ok=True)
shutil.copy2(sys.executable, ROOT / 'python/bin/python3.11')
shutil.copytree('/usr/local/lib/python3.11', ROOT / 'python/lib/python3.11',
                ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '_tkinter*', 'tkinter', 'idlelib', 'config-*'), symlinks=False)
for name in ('dumpcap', 'tcpdump'):
    shutil.copy2(shutil.which(name), ROOT / f'bin/{name}.elf')

# ldd reports transitive dependencies, including those of extension modules.
def is_dynamic_elf(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open('rb') as handle:
        header = handle.read(18)
    return header[:4] == b'\x7fELF' and int.from_bytes(header[16:18], 'little') in (2, 3)


elfs = [p for p in ROOT.rglob('*') if is_dynamic_elf(p)]
libraries: dict[str, Path] = {}
for elf in elfs:
    result = subprocess.run(['ldd', str(elf)], capture_output=True, text=True, check=True)
    if 'not found' in result.stdout:
        raise RuntimeError(f'unresolved library in {elf}: {result.stdout}')
    for source in re.findall(r'(/[^\s()]+)', result.stdout):
        path = Path(source)
        if path.is_file():
            previous = libraries.get(path.name)
            if previous and previous.read_bytes() != path.read_bytes():
                raise RuntimeError(f'library name collision: {path.name}')
            libraries[path.name] = path
for name, source in libraries.items():
    shutil.copy2(source, ROOT / 'lib' / name)
loader = next(name for name in libraries if name.startswith('ld-linux'))
shutil.copy2(ROOT / 'lib' / loader, ROOT / 'lib/ld.so')
shutil.copy2('/etc/ssl/certs/ca-certificates.crt', ROOT / 'ca-certificates.crt')
for source in Path('/usr/share/doc').glob('*/copyright'):
    shutil.copy2(source, ROOT / 'licenses' / f'{source.parent.name}.copyright')

for name, executable in [('python', 'python/bin/python3.11'),
                         ('dumpcap', 'bin/dumpcap.elf'), ('tcpdump', 'bin/tcpdump.elf')]:
    wrapper = ROOT / 'bin' / name
    wrapper.write_text('''#!/bin/sh
set -eu
R="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH PYTHONPATH PYTHONSTARTUP PYTHONUSERBASE
export PYTHONHOME="$R/python" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1
export SSL_CERT_FILE="$R/ca-certificates.crt" REQUESTS_CA_BUNDLE="$R/ca-certificates.crt"
export PATH="$R/bin:/usr/sbin:/usr/bin:/sbin:/bin"
exec "$R/lib/ld.so" --inhibit-cache --library-path "$R/lib" "$R/''' + executable + '''" "$@"
''', encoding='utf-8')
    wrapper.chmod(0o755)

metadata = {
    'format': 1, 'self_contained': True,
    'arch': {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()],
    'python': platform.python_version(), 'libc': platform.libc_ver(),
    'python_packages': {d.metadata['Name']: d.version for d in importlib.metadata.distributions()},
    'capture': ['dumpcap', 'tcpdump'],
    'requirements_sha256': hashlib.sha256(Path('/tmp/requirements.txt').read_bytes()).hexdigest(),
}
(ROOT / 'runtime.json').write_text(json.dumps(metadata, indent=2) + '\n')
subprocess.run([str(ROOT / 'bin/python'), '-c',
                'import ssl,tomllib,sqlite3,ctypes,psutil,regex,requests,openpyxl; print("runtime ok")'],
               check=True)
for name in ('dumpcap', 'tcpdump'):
    subprocess.run([str(ROOT / 'bin' / name), '--version'], check=True, capture_output=True)
with tarfile.open('/out/runtime.tar.gz', 'w:gz') as archive:
    archive.add(ROOT, arcname='runtime')
shutil.copy2(ROOT / 'runtime.json', '/out/runtime.json')
