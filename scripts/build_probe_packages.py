#!/usr/bin/env python3
"""Build reproducible Probe packages for server-side deployment.

Publishes ``probe_packages/probe-<version>/<arch>/`` containing the runtime
files plus a ``manifest.json`` and a single signed-by-hash ``.tar.gz`` artifact.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probe"
OUT = ROOT / "probe_packages"
VERSION = "3.7.0"
ARCHS = ["amd64", "arm64"]
FILES = [
    "install.sh",
    "run-probe.sh",
    "runtime_check.py",
    "uninstall.sh",
    "probe.py",
    "scanner.py",
    "data_assets.py",
    "ruleset_client.py",
    "requirements.txt",
    "data-security-toolbox-probe.service",
]
# Directory trees copied verbatim, keyed by source directory and installed
# under the same relative path. The detection engine is shared with the
# platform, so the package has to carry it: probe.py imports
# `shared.sensitive_detection` from its parent directory (APP_DIR).
TREES = {ROOT / "shared": "shared"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_text(source: Path, destination: Path) -> None:
    """Copy a package member as Linux-readable text.

    The builder also runs on Windows checkouts (`core.autocrlf=true`), where
    copying bytes verbatim would ship CRLF to the target host: bash reads
    `set -euo pipefail` followed by a carriage return as an unknown option and
    aborts the install with `set: pipefail : invalid option name`, and systemd
    stops parsing the unit. Windows also has no POSIX mode bits, so the
    executable bit of the installer is set here, not inherited from the
    checkout.
    """
    data = source.read_bytes().replace(b"\r\n", b"\n")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    destination.chmod(0o755 if source.suffix == ".sh" else 0o644)


def tar_member(info: tarfile.TarInfo) -> tarfile.TarInfo:
    """Store POSIX modes and root ownership in the artifact.

    `tar.add` records `st_mode` from disk, which on Windows is 0o666 for every
    file: an extracted `install.sh` would not be executable.
    """
    info.mode = 0o755 if info.isdir() or info.name.endswith(".sh") else 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def copy_trees(pkg_dir: Path) -> list[str]:
    """Copy the shared runtime trees, returning their package-relative paths."""
    copied: list[str] = []
    for source, arc_dir in TREES.items():
        if not source.is_dir():
            raise SystemExit(f"missing runtime directory: {source}")
        for path in sorted(source.rglob("*.py")):
            relative = f"{arc_dir}/{path.relative_to(source).as_posix()}"
            destination = pkg_dir / relative
            copy_text(path, destination)
            copied.append(relative)
    if not copied:
        raise SystemExit(f"no runtime files found in: {', '.join(str(item) for item in TREES)}")
    return copied


def build(arch: str) -> tuple[Path, str]:
    pkg_dir = OUT / f"probe-{VERSION}" / arch
    pkg_dir.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        copy_text(PROBE / name, pkg_dir / name)
    # `shared/sensitive_detection` must be installable next to `probe/`.
    tree_files = copy_trees(pkg_dir)
    runtime_dir = OUT / "runtimes" / arch
    runtime_archive = runtime_dir / "runtime.tar.gz"
    metadata_path = runtime_dir / "runtime.json"
    if not runtime_archive.is_file() or not metadata_path.is_file():
        raise SystemExit(f"missing {arch} runtime: run scripts/build_probe_runtime.py --arch {arch}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("arch") != arch or not metadata.get("self_contained"):
        raise SystemExit("runtime architecture or format mismatch")
    if sha256(runtime_archive) != metadata.get("sha256"):
        raise SystemExit("runtime digest mismatch")
    requirements = (PROBE / "requirements.txt").read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(requirements).hexdigest() != metadata.get("requirements_sha256"):
        raise SystemExit("runtime dependencies are stale: rebuild the runtime")
    shutil.copy2(runtime_archive, pkg_dir / "runtime.tar.gz")
    bundled = ["runtime.tar.gz"]
    artifact = pkg_dir / f"probe-{VERSION}-{arch}.tar.gz"
    members = [*FILES, *tree_files, *bundled]
    with tarfile.open(artifact, "w:gz") as tar:
        for name in members:
            tar.add(pkg_dir / name, arcname=name, filter=tar_member)
    digest = sha256(artifact)
    manifest = {
        "version": VERSION,
        "arch": arch,
        "python_min": "3.11",
        "runtime": metadata,
        "supported_os": ["debian", "ubuntu", "rhel", "rocky", "centos"],
        "artifact": artifact.name,
        "sha256": digest,
        "files": members,
    }
    (pkg_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return pkg_dir, digest


def main() -> None:
    # ``--arch`` lets an arm64-only host (or a partial rebuild) package just the
    # runtime it actually has, instead of failing on the missing one.
    wanted = [item.split("=", 1)[1] for item in sys.argv[1:] if item.startswith("--arch=")]
    arches = wanted or ARCHS
    for arch in arches:
        if arch not in ARCHS:
            raise SystemExit(f"unknown arch: {arch} (expected one of {', '.join(ARCHS)})")
        path, digest = build(arch)
        print(f"built {path} sha256={digest}")



if __name__ == "__main__":
    main()
