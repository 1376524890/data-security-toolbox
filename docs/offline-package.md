# x86_64 Linux 离线交付包

面向 **x86_64 Linux** 的一键离线部署包，已在**银河麒麟桌面操作系统 V10 SP1** 与 **Ubuntu 22.04 LTS**
上核对。镜像本身与发行版无关，目标机不需要外网、不需要构建、不需要访问任何镜像仓库：镜像、探针分发包、
探针自带运行时与 Docker Compose v2 插件全部随包。

## 产物

| 名称 | 说明 |
| --- | --- |
| `dst-toolbox-2.14.0-linux-x86_64.tar.gz` | 交付给现场的整包（含 `images/` 镜像归档与 `CHECKSUMS.sha256`） |
| `dst-toolbox-2.14.0-linux-x86_64/` | 未压缩的打包暂存目录（同一内容，便于本地核对） |

## 包内结构

```
dst-toolbox-2.14.0-linux-x86_64/
  deploy.sh                 一键部署：加载镜像 → 选端口 → 生成 .env → 启动 → 迁移 → 初始化 → 汇总地址
  undeploy.sh               停止（默认保留数据卷，--volumes 才删除）
  load-images.sh            加载 images/ 下全部镜像
  docker-compose.yml        基础编排（与仓库同源）
  docker-compose.offline.yml 离线覆盖：把服务固定到本包镜像标签
  .env.example              环境变量模板
  images/                   dst-toolbox-2.14.0-images.tar.gz（8 个镜像，约 2.6 GB）
  probe_packages/probe-3.7.0/{amd64,arm64}/   采集探针安装包（含自带运行时 runtime.tar.gz）
  probe-offline/            探针离线安装包装脚本（解释器与依赖都在探针包内）
  tools/                    docker-compose-linux-x86_64（Compose v2 插件）
  data_security_toolbox_manual_testpack/   compose 声明的只读挂载点（空目录）
  .local/deployment/                       compose 声明的部署目录（首启为空）
  backend/ frontend/ shared/ probe/ scripts/ docs/   同源源码快照（审计/重建用，运行非必需）
  VERSION  CHECKSUMS.sha256
```

## 目标机前置条件

1. **Docker Engine 20.10+**，`docker info` 可用；架构 `amd64`。两个平台都不预装 Docker：
   - **Ubuntu 22.04 LTS**：官方 Docker CE（`docker-ce` + `docker-ce-cli` + `containerd.io`）或系统源
     `docker.io`（20.10.12）。**不要**用 `apt install docker-compose`：那是 Compose v1，本包 compose
     文件没有顶层 `version:` 键，v1 无法解析。
   - **银河麒麟 V10 SP1**：离线 rpm/deb 或内网源安装。
2. **Docker Compose v2**：缺失时 `deploy.sh` 会自动把 `tools/docker-compose-linux-x86_64` 装到
   `/usr/local/lib/docker/cli-plugins/`。
3. 端口：默认 **8080**（管理台）/ **8000**（API / 探针接入）。**被占用不需要事先处理**——`deploy.sh`
   （修订号 `r5`，启动时会打印 `deploy.sh rN`）会按 18080–18120 / 18000–18040 自动挑空闲端口并写进
   `.env`，结尾按实际端口打印地址；要固定端口就用 `--port` / `--api-port` 显式指定（冲突直接报错）。
   放行按发行版（放行实际使用的端口）：
   麒麟 `sudo firewall-cmd --permanent --add-port=8080/tcp --add-port=8000/tcp && sudo firewall-cmd --reload`；
   Ubuntu `sudo ufw allow 8080/tcp && sudo ufw allow 8000/tcp`。
4. 磁盘预留 ≥30 GB（镜像约 6 GB，数据库与抓包/证据随使用增长）。
5. **探针主机不需要任何前置依赖**：3.7.0 的探针包自带 CPython 3.11、全部 Python 依赖（含 `regex`、
   `openpyxl`）、`dumpcap`/`tcpdump`、它们的 ELF 库闭包、私有动态加载器与 CA 证书；安装时不执行 pip、
   apt，也不写 `/usr/local/bin`。平台预检改用这个自带运行时探测目标机（不再检查主机 Python 与抓包工具）。
   主机侧只需 systemd 与基础 coreutils/shadow 工具（`tar`、`systemctl`、`useradd`、`id`、`chown`、
   `find`、`mktemp`），`install.sh` 缺命令时一次性列出后退出；启动脚本 `run-probe.sh` 自设 `PATH` 并固定
   `PYTHONUTF8=1`/`PYTHONIOENCODING=utf-8`，主机不设 `LANG` 也能正常写中文日志。

部署命令（详见包内 `README-离线部署.md`）：

```bash
tar -xzf dst-toolbox-2.14.0-linux-x86_64.tar.gz
cd dst-toolbox-2.14.0-linux-x86_64
sudo ./deploy.sh                               # 默认 8080/8000；被占用会自动换空闲端口
sudo ./deploy.sh --port 8443 --api-port 8001    # 需要固定端口时显式指定
```

## 如何重新打包（在本机 Windows 上执行）

打包脚本位于工作区（仓库外）`dist-linux-build/`，以下命令的工作目录是工作区根目录（同时含
`00-数据安全工具箱/` 与 `dist-linux-build/` 的那一层）：

```powershell
$py = ".\00-数据安全工具箱\source\.venv\Scripts\python.exe"
& $py dist-linux-build\make_bundle.py      # 组装源码/脚本/探针包，保留 images/
& $py dist-linux-build\save_images.py      # 打发布标签并导出 images/*.tar.gz
& $py dist-linux-build\finalize_bundle.py  # 写 CHECKSUMS.sha256 并生成外层 tar.gz
& $py dist-linux-build\verify_bundle.py    # 解包校验：文件名编码、逐文件校验和、镜像归档
```

- 版本号写在 `make_bundle.py` / `save_images.py` / `finalize_bundle.py` 的 `VERSION` 与
  `make_bundle.py` 的 `PROBE_VERSION`；升级时必须与仓库内四处探针版本声明同步。
- `make_bundle.py` 会清空暂存目录但**保留 `images/`**，因此改文档后可以安全重跑；只重新导出镜像时
  单独重跑 `save_images.py` 即可。
- **改了 `deploy.sh` 模板 / compose / 包内文档后，必须重跑 `make_bundle.py` → `finalize_bundle.py` →
  `verify_bundle.py`**，否则包内仍是旧副本；同时把 `make_bundle.py` 的 `DEPLOY_REV` 加一。现场靠
  `deploy.sh` 启动日志里的 `deploy.sh rN` 判断手上是不是新包——真机上就因为拿的是旧包白排查了一轮。
- `CHECKSUMS.sha256` 必须用 **LF** 换行写出（GNU `sha256sum -c` 会把行尾 CR 当成文件名的一部分）；
  `finalize_bundle.py` 按字节写出，`verify_bundle.py` 会显式检查这一点。
- `save_images.py` 导出 5 个应用镜像（`dst-toolbox/{backend,worker,beat,deployment-worker,frontend}:<版本>`）
  以及 `postgres:16.6-alpine`、`redis:7.4-alpine`、`mher/flower:2.0.1`，并从归档里读回 `manifest.json`
  逐一校验标签。
- 探针自带运行时由 `scripts/build_probe_runtime.py --arch amd64 --arch arm64` 在**构建机**上生成
  （Docker + `python:3.11-slim` + tshark/tcpdump，目标机不参与）：产物是
  `probe_packages/runtimes/<arch>/runtime.tar.gz` 与同名 `runtime.json`（记录架构、Python 版本、
  依赖清单与 sha256）。随后 `scripts/build_probe_packages.py` 把它打进各架构探针包；
  `probe/requirements.txt` 变化时打包会直接拒绝（`runtime dependencies are stale`）。**顺序不能反**：
  先建运行时、再建探针包。
- `install-probe-offline.sh` 只负责按目标架构调用包内 `install.sh`；它不接受 `--python` / `--wheels`，
  也不探测或修改主机 Python。Compose 插件取 Docker 官方 `docker/compose` 发布的
  `docker-compose-linux-x86_64`。

## 交付口径

- 包内**不含**任何测试数据；`TEST_DATA_IMPORT_ENABLED=false`，`APP_ENV=production` 时该开关会被拒绝。
- 前端为生产构建，未启用 `VITE_DEMO_MODE`。
- 镜像与源码快照来自同一工作树；`sha256sum -c CHECKSUMS.sha256` 可校验整包完整性。

## 本版实测数据

- 镜像归档 `images/dst-toolbox-2.14.0-images.tar.gz` = 1255.1 MB，含 8 个标签，导出后已回读校验
  （`beat`/`deployment-worker` 与 `worker` 是同一个镜像 ID，`docker save` 已去重）。
- 外层交付包 `dst-toolbox-2.14.0-linux-x86_64.tar.gz` ≈ 1.34 GB；解包后 1004 个文件全部通过
  `CHECKSUMS.sha256` 校验，文件名全部是合法 UTF-8（中文名不会变乱码），且不含绝对路径或 `..` 路径。
- `tools/docker-compose-linux-x86_64` 已验证为 ELF 64-bit LSB x86-64 可执行文件（75 108 694 字节）。
- `docker compose -f docker-compose.yml -f docker-compose.offline.yml config -q` 在本机通过，
  8 个服务全部解析到包内镜像标签（无 build、无 registry 拉取）。
- 平台 2.14.0 / 探针 3.7.0（自带运行时 24.5 MB/架构，`runtime.tar.gz` 内含私有解释器与库闭包）/
  迁移 head `0017_file_sources`。
- **真机（Ubuntu 22.04 LTS，Docker 29.2.1 + compose 5.0.2）**：用探针 3.6.0 版包以 `--port 18088 --api-port 8001` 部署成功
  （该机 8080 被主机进程 `console-gateway`、8000 被另一产品容器 `llmsec-protected` 占用）；幂等重跑 exit 0
  且端口保持；`/api/v1/health` 200、`openapi.json` 2.14.0、`alembic current` = `0017_file_sources (head)`。探针 3.7.0 版包还没在真机部署过。
- 整包 sha256 每次重打包都会变，交付记录（`TASK.md` / `PROJECT_STATUS.md`）里给出当次指纹，以那份为准。
