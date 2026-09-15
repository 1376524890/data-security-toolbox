"""Probe package selection and trusted-digest verification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from app.core.config import settings


class PackageError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_arch(arch: str) -> str:
    value = arch.strip().lower()
    if value in {"x86_64", "amd64"}:
        return "amd64"
    if value in {"aarch64", "arm64"}:
        return "arm64"
    raise PackageError(f"unsupported architecture: {arch}")


def find_package(arch: str, version: str | None = None) -> dict[str, Any]:
    """Return the verified package descriptor for ``arch``.

    ``version`` defaults to the configured probe agent version. The archive
    digest in ``manifest.json`` is treated as trusted source; the actual
    artifact is re-hashed here and compared to reject tampering or a
    stale/partially-replaced package directory.
    """
    norm = _normalize_arch(arch)
    version = version or settings.probe_agent_version
    pkg_dir = settings.deployment_package_dir / f"probe-{version}" / norm
    manifest_path = pkg_dir / "manifest.json"
    if not manifest_path.is_file():
        raise PackageError(f"package manifest not found: {manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PackageError("invalid package manifest") from exc
    if str(manifest.get("version", "")) != version:
        raise PackageError(f"package version {manifest.get('version')} != {version}")
    if _normalize_arch(str(manifest.get("arch", ""))) != norm:
        raise PackageError("package architecture mismatch")
    artifact_name = manifest.get("artifact", "")
    if not artifact_name or "/" in artifact_name or "\\" in artifact_name or ".." in artifact_name:
        raise PackageError("invalid artifact name")
    artifact = (pkg_dir / artifact_name).resolve()
    if not artifact.is_file() or pkg_dir.resolve() not in artifact.parents:
        raise PackageError("package artifact missing or outside package dir")
    digest = sha256_file(artifact)
    if not str(manifest.get("sha256", "")).lower() == digest.lower():
        raise PackageError("package digest mismatch")
    files = manifest.get("files", [])
    missing = [name for name in files if not (pkg_dir / name).is_file()]
    if missing:
        raise PackageError(f"package missing files: {', '.join(missing)}")
    return {
        "dir": pkg_dir,
        "manifest": manifest,
        "artifact": artifact,
        "sha256": digest,
        "version": version,
        "arch": norm,
    }


def list_packages() -> list[dict[str, Any]]:
    root = settings.deployment_package_dir
    if not root.is_dir():
        return []
    items: list[dict[str, Any]] = []
    for version_dir in sorted(root.glob("probe-*")):
        if not version_dir.is_dir():
            continue
        version = version_dir.name.split("probe-", 1)[-1]
        for arch_dir in sorted(version_dir.iterdir()):
            if not arch_dir.is_dir():
                continue
            try:
                info = find_package(arch_dir.name, version)
                items.append({"version": version, "arch": info["arch"], "sha256": info["sha256"]})
            except PackageError:
                continue
    return items
