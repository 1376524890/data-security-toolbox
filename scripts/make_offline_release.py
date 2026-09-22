#!/usr/bin/env python3
"""Build the offline delivery bundle: ``dist-release/dst-toolbox-<ver>-linux-<arch>.tar.gz``.

The bundle is what goes to a customer site: every image, the probe packages, the
whole source tree (so the platform can keep being developed on the target host)
and the one-click ``deploy.sh`` / ``deploy.conf`` pair. It is staged with hard
links, so the ~3.5 GB tree costs no extra disk, then archived once with GNU tar
(explicit uid/gid and preserved exec bits).

Run ``scripts/offline_bundle.py --save`` first: this script refuses to build a
release whose image archive is missing, because a bundle without images cannot
be deployed offline.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT_ROOT = ROOT / "dist-release"
IMAGES_TAR = ROOT / "dist-offline" / "security-toolbox-images.tar"
PROBE_PACKAGE = ROOT / "probe_packages" / "probe-3.7.0" / "arm64" / "probe-3.7.0-arm64.tar.gz"

#: Top-level entries that never belong in a delivery bundle: build outputs of
#: earlier releases, the live data directory, local scratch trees, and the
#: operator's own documents (screenshots, Word files) that happen to sit in the
#: working copy.
SKIP_TOP = {
    "dist-release", "dist-deploy", "dist-deploy.tar", "dist-deploy.zip",
    "deploy-data", "data", "0916_v2.7", ".refactor-trash", ".ruff_cache",
    ".pytest_cache", ".local",
    # The operator's .env holds the live passwords and the site IP. Shipping it
    # would hand the same credentials to every site and make the target reuse
    # the build host's values, so only .env.example travels; deploy.sh writes a
    # fresh .env from deploy.conf on first run.
    ".env",
}
SKIP_PREFIX = ("ChatGPT Image", "FRICSE")
SKIP_ENV_PREFIX = ".env."
#: Paths that are runtime state, not source.
SKIP_REL = {"backend/data", "frontend/node_modules/.vite"}


def skipped(name: str) -> bool:
    if name in SKIP_TOP or name.startswith(SKIP_PREFIX):
        return True
    return name.startswith(SKIP_ENV_PREFIX) and name != ".env.example"


def platform_version() -> str:
    return json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))["version"]


def host_arch() -> str:
    """The daemon's architecture in OCI spelling (arm64 / amd64)."""
    return subprocess.run(
        ["docker", "version", "--format", "{{.Server.Arch}}"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def link_tree(src: pathlib.Path, dst: pathlib.Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for entry in src.iterdir():
        rel = str(entry.relative_to(ROOT))
        if rel in SKIP_REL or entry.name == "__pycache__":
            continue
        target = dst / entry.name
        if entry.is_symlink():
            os.symlink(os.readlink(entry), target)
        elif entry.is_dir():
            link_tree(entry, target)
        else:
            try:
                os.link(entry, target)
            except OSError:  # cross-device fallback
                shutil.copy2(entry, target)


def stage(name: str, arch: str, version: str) -> pathlib.Path:
    out = OUT_ROOT / name
    if out.exists():
        shutil.rmtree(out)
    # Top-level files are hard-linked into `out` before any directory entry has
    # created it (`.dockerignore` sorts first), so the root must exist up front.
    out.mkdir(parents=True, exist_ok=True)
    for entry in sorted(ROOT.iterdir()):
        if skipped(entry.name):
            continue
        if entry.is_dir():
            link_tree(entry, out / entry.name)
        else:
            try:
                os.link(entry, out / entry.name)
            except OSError:
                shutil.copy2(entry, out / entry.name)

    # deploy/ is the versioned master copy; at the bundle root the operator gets
    # ./deploy.sh (one command) next to docker-compose.yml.
    for item in sorted((ROOT / "deploy").iterdir()):
        shutil.copy2(item, out / item.name)
    (out / ".local" / "deployment").mkdir(parents=True, exist_ok=True)

    (out / "VERSION").write_text(
        "Data Security Toolbox（数据安全工具箱）\n"
        f"平台版本 platform : {version}\n"
        "探针版本 probe    : 3.7.0\n"
        "数据库迁移 head   : 0019_policy_group_fingerprints\n"
        f"镜像架构 arch     : {arch} / linux（目标机 uname -m 必须是 aarch64）\n"
        f"Git 修订          : {git_rev()}\n",
        encoding="utf-8",
    )
    checks = [IMAGES_TAR, PROBE_PACKAGE]
    lines = []
    for path in checks:
        if path.exists():
            digest = subprocess.run(["sha256sum", str(path)], capture_output=True, text=True,
                                    check=True).stdout.split()[0]
            lines.append(f"{digest}  {path.relative_to(ROOT)}")
    (out / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def git_rev() -> str:
    return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip() or "unknown"


def archive(staged: pathlib.Path) -> pathlib.Path:
    tar_path = OUT_ROOT / f"{staged.name}.tar.gz"
    if tar_path.exists():
        tar_path.unlink()
    # --hard-dereference: the staging tree is hard-linked to the working copy, so
    # store real file bodies instead of link entries that would dangle outside it.
    with tar_path.open("wb") as handle:
        # gzip -1: the payload is mostly uncompressed docker layers (docker save
        # writes them as plain tar), so a fast level already gets ~2.8x.
        tar = subprocess.Popen(
            ["tar", "--hard-dereference", "--owner=0", "--group=0", "--numeric-owner",
             "-cf", "-", staged.name],
            cwd=OUT_ROOT, stdout=subprocess.PIPE,
        )
        subprocess.run(["gzip", "-1"], stdin=tar.stdout, stdout=handle, check=True)
        if tar.wait() != 0:
            sys.exit("tar 失败")
    digest = subprocess.run(["sha256sum", str(tar_path)], capture_output=True, text=True,
                            check=True).stdout.split()[0]
    # Not with_suffix(): it would replace only the last suffix and produce
    # "….tar.tar.gz.sha256".
    checksum = tar_path.parent / (tar_path.name + ".sha256")
    checksum.write_text(f"{digest}  {tar_path.name}\n", encoding="utf-8")
    return tar_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=None, help="默认取 frontend/package.json")
    parser.add_argument("--arch", default=None, help="默认取 docker 守护进程架构")
    parser.add_argument("--no-archive", action="store_true", help="只暂存，不打 tar.gz")
    args = parser.parse_args()

    version = args.version or platform_version()
    arch = args.arch or host_arch()
    name = f"dst-toolbox-{version}-linux-{arch}"

    if not IMAGES_TAR.exists():
        sys.exit("缺少 dist-offline/security-toolbox-images.tar，先跑：python3 scripts/offline_bundle.py --save")

    staged = stage(name, arch, version)
    files = sum(1 for f in staged.rglob("*") if f.is_file())
    print(f"暂存完成：{staged}（{files} 个文件）")
    if args.no_archive:
        return
    tar_path = archive(staged)
    size = tar_path.stat().st_size / 1e9
    print(f"交付包：{tar_path}（{size:.2f} GB）")
    print(f"校验：{(tar_path.parent / (tar_path.name + '.sha256')).read_text(encoding='utf-8').strip()}")


if __name__ == "__main__":
    main()
