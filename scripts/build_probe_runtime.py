"""Build/export offline runtimes with Docker (build host only, never the target)."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(arch: str) -> None:
    output = ROOT / 'probe_packages/runtimes' / arch
    output.mkdir(parents=True, exist_ok=True)
    # Legacy Docker builds can pick the host architecture for a multi-platform digest.
    # An explicitly-platformed build container avoids that bug without buildx.
    cid = 'dst-runtime-build-' + uuid.uuid4().hex[:12]
    image = 'python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534'
    try:
        subprocess.run([
            'docker', 'run', '--name', cid, '--platform', f'linux/{arch}',
            '--mount', f'type=bind,source={ROOT / "scripts/probe-runtime"},target=/build,readonly',
            '--mount', f'type=bind,source={ROOT / "probe/requirements.txt"},target=/tmp/requirements.txt,readonly',
            image, 'sh', '/build/build.sh', arch,
        ], check=True)
        for name in ('runtime.tar.gz', 'runtime.json'):
            subprocess.run(['docker', 'cp', f'{cid}:/out/{name}', str(output / name)], check=True)
    finally:
        subprocess.run(['docker', 'rm', cid], check=True)
    path = output / 'runtime.json'
    metadata = json.loads(path.read_text())
    if metadata['arch'] != arch:
        raise RuntimeError(f'built architecture {metadata["arch"]} != requested {arch}')
    with (output / 'runtime.tar.gz').open('rb') as handle:
        metadata['sha256'] = hashlib.file_digest(handle, 'sha256').hexdigest()
    path.write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print(f'exported {arch}: {metadata["sha256"]}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], action='append')
    args = parser.parse_args()
    for architecture in args.arch or ['amd64', 'arm64']:
        build(architecture)
