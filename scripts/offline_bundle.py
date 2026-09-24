#!/usr/bin/env python3
"""Build the offline bundle: offline data plus (optionally) the image tarball.

The tarball is what an air-gapped host loads with ``docker load``. Images are
saved with the architecture they were built for, so the bundle must be produced
on -- or built for -- the target architecture: an ``aarch64`` host needs an
``aarch64`` bundle, and an ``x86_64`` tarball will not run there. The script
checks that before it writes anything, because a wrong-arch tarball only fails
later, on the target machine, in the middle of a deployment.

``docker save`` is skipped by default (it is a multi-GB write); pass ``--save``
when the tarball itself is the deliverable.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "dist-offline"
TARBALL = "security-toolbox-images.tar"


def _run(*args: str) -> str:
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"命令失败：{' '.join(args)}\n{result.stderr.strip()}")
    return result.stdout.strip()


def host_arch() -> str:
    """The architecture the daemon builds for, in the OCI spelling.

    ``docker info`` reports the kernel's name (``aarch64`` / ``x86_64``) while
    ``docker image inspect`` reports the OCI name (``arm64`` / ``amd64``);
    comparing the two without normalising rejects every bundle.
    """
    return _run("docker", "version", "--format", "{{.Server.Arch}}")


def compose_images() -> list[str]:
    """Every image ``docker-compose.yml`` needs, in a stable order.

    Read from compose rather than hard-coded: the tag list drifted once already
    (``security-toolbox-*`` -> ``source-*``) and a stale README is how a bundle
    ends up missing an image on the target host.
    """
    output = _run("docker", "compose", "-f", "docker-compose.yml", "config", "--images")
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def check_architecture(images: list[str], arch: str) -> None:
    missing: list[str] = []
    foreign: list[str] = []
    for image in images:
        try:
            image_arch = _run("docker", "image", "inspect", image, "--format", "{{.Architecture}}")
        except SystemExit:
            missing.append(image)
            continue
        if image_arch != arch:
            foreign.append(f"{image} ({image_arch})")
    if missing:
        sys.exit("本机缺少镜像，先构建：\n  " + "\n  ".join(missing))
    if foreign:
        sys.exit(f"镜像架构与目标机 {arch} 不一致，目标机无法运行：\n  " + "\n  ".join(foreign))


def save_images(images: list[str], tar_path: Path) -> None:
    _run("docker", "save", "-o", str(tar_path), *images)


def readme(images: list[str], arch: str, saved: bool) -> str:
    tar_step = (
        f"已经生成镜像包 dist-offline/{TARBALL}（{arch}）"
        if saved
        else f"生成镜像包（本机当前架构 {arch}，目标机必须是同一架构）：\n"
             f"  docker save -o dist-offline/{TARBALL} " + " ".join(images)
    )
    return (
        "数据安全监测检测工具箱 离线包\n"
        "\n"
        "架构：本包内镜像为 " + arch + "，目标机 uname -m 必须一致（aarch64 / x86_64 不可混用）。\n"
        "\n"
        "一、联网的构建机（架构需与目标机相同）\n"
        "1. 构建镜像：\n"
        "   DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target api "
        "-t source-backend:latest .\n"
        "   DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target analysis-worker "
        "-t source-worker:latest -t source-deployment-worker:latest .\n"
        "   DOCKER_BUILDKIT=0 docker build -t source-frontend:latest ./frontend\n"
        "2. " + tar_step + "\n"
        "3. 随包拷贝：dist-offline/、docker-compose.yml、.env（确认里面没有 DATA_ROOT）\n"
        "\n"
        "二、目标内网机（无外网）\n"
        "1. docker load -i " + TARBALL + "\n"
        "2. 离线启动，禁止拉取与构建；缺镜像会直接报错而不是悄悄去拉：\n"
        "   PULL_POLICY=never docker compose -p source -f docker-compose.yml up -d "
        "--no-build --pull never\n"
        "3. docker compose -p source -f docker-compose.yml ps   # 等到 backend 显示 healthy\n"
        "4. 导入离线规则 / IOC / CVE：\n"
        "   docker compose -p source exec backend python -c \"from app.core.database import "
        "SessionLocal; from app.integrations.offline_manager import import_offline_path; "
        "import pathlib; db=SessionLocal(); print(import_offline_path(db, "
        "pathlib.Path('/app/data/offline'), resource_type=None, name='bundle', version='1.0')"
        ".to_dict()); db.close()\"\n"
        "\n"
        "三、镜像清单（" + str(len(images)) + " 个）\n"
        + "".join(f"  - {image}\n" for image in images)
        + "\n"
        "四、数据持久化\n"
        "  postgres / redis / backend 数据都在宿主机目录 deploy-data/，不在匿名卷里；\n"
        "  容器重建（--force-recreate）不会丢数据。db 里跑的是 alembic upgrade head，随连接启动。\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--save", action="store_true",
                        help=f"同时生成 dist-offline/{TARBALL}（多 GB）")
    parser.add_argument("--skip-arch-check", action="store_true",
                        help="跳过架构校验（仅在明知架构不同却仍要打包时使用）")
    args = parser.parse_args()

    arch = host_arch()
    images = compose_images()
    if not args.skip_arch_check:
        check_architecture(images, arch)

    TARGET.mkdir(parents=True, exist_ok=True)
    data_dir = ROOT / "backend" / "app" / "integrations" / "offline_data"
    if data_dir.exists():
        shutil.copytree(data_dir, TARGET / "data", dirs_exist_ok=True)

    if args.save:
        save_images(images, TARGET / TARBALL)

    (TARGET / "README.txt").write_text(readme(images, arch, args.save), encoding="utf-8")
    print(f"离线包已写入 {TARGET}（架构 {arch}，镜像 {len(images)} 个）")
    if not args.save:
        print(f"未生成镜像包；需要时执行：docker save -o dist-offline/{TARBALL} "
              + " ".join(images))


if __name__ == "__main__":
    main()
