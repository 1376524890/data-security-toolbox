#!/usr/bin/env python3
"""Build reproducible Probe packages for server-side deployment.

Publishes ``probe_packages/probe-<version>/<arch>/`` containing the runtime
files plus a ``manifest.json`` and a single signed-by-hash ``.tar.gz`` artifact.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probe"
OUT = ROOT / "probe_packages"
VERSION = "3.5.0"
ARCHS = ["amd64", "arm64"]
FILES = [
    "install.sh",
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
BIN_NAMES = ["dumpcap", "tcpdump"]


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
    # Optional capture-tool binaries (placed at probe_packages/bin/<arch>/).
    bundled: list[str] = []
    for bin_name in BIN_NAMES:
        src_bin = OUT / "bin" / arch / bin_name
        if src_bin.is_file():
            dest_dir = pkg_dir / "bin"
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_bin, dest_dir / bin_name)
            bundled.append(f"bin/{bin_name}")
    # Optional offline wheels (placed at probe_packages/wheels/).
    if (OUT / "wheels").is_dir() and any((OUT / "wheels").glob("*.whl")):
        shutil.copytree(OUT / "wheels", pkg_dir / "wheels", dirs_exist_ok=True)
        bundled.append("wheels")
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
        "supported_os": ["debian", "ubuntu", "rhel", "rocky", "centos"],
        "artifact": artifact.name,
        "sha256": digest,
        "files": members,
    }
    (pkg_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return pkg_dir, digest


def main() -> None:
    for arch in ARCHS:
        path, digest = build(arch)
        print(f"built {path} sha256={digest}")

    if (OUT / "bin").exists():
        print("note: bundled capture-tool binaries found in probe_packages/bin/")
    if (OUT / "wheels").exists():
        print("note: offline wheels found in probe_packages/wheels/")


if __name__ == "__main__":
    main()
