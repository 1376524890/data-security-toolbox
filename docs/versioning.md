# 版本与分支管理

## 分支

- `main`：稳定发布分支，只接受经过验收的合并
- `develop`：集成开发分支
- `feature/*`：功能分支，从 `develop` 创建，完成后合并回 `develop`

## 版本

- `v0.1` 基础框架
- `v0.2` Probe
- `v0.3` 任务系统
- `v0.4` 资产 + 元数据
- `v0.5` PCAP 分析
- `v0.6` 流量分析
- `v1.0` 完整系统
- `v2.0` 平台化改造与离线部署
- `v2.1` 完整功能闭环
- `v2.2` 探针情报与网络防泄密
- `v2.5` 多网卡探针、规则库、检查规则
- `v2.6` 网络扫描可靠性修复与探针数据资产采集
- `v2.7` 防泄密检测质量与告警阈值（探针任务停止 / 删除）
- `v2.8` 数据发现与对象模型（共享敏感引擎、规则集、扫描配置、资产对象），探针 3.4.0
- `v2.9` 探针入网与部署可靠性修复、明文私钥检测基线、网络 DLP 原始字节证据，探针 3.4.1
- `v2.10` 探针卸载（远程回收主机、生产文件清理与审计）、一键删除先卸载再删记录，探针 3.5.0
- `v2.11` 引擎规则库（规则文件真实加载、上游规则在线同步、命中规则快照与解释）、引擎总览页、
  PCAP 工作台（传输文件提取与文本/Hex 预览、上传定位），探针 3.5.0
- `v2.13` 结构与状态解耦（后端按域拆路由与编排入口、前端页面状态收进 composable），接口与数据表不变
- `v2.14` 共享文件来源（FTP/FTPS/SFTP）、数据库直连盘点（MySQL/MariaDB/PostgreSQL）、统一规则源与命中
  原文回传，探针 3.6.0（2026-09-21 交付更新：探针 3.7.0 自带运行时，见下文）

发布时创建 `vX.Y.Z` 注释标签。

## 提交信息

使用 Conventional Commits：`feat:`、`fix:`、`docs:`、`test:`、`chore:`。

## v2.12.0 发布例外（2026-09-19）

本次发布业务逻辑与数据真实性整改，新增迁移 `0015_alert_hits`。遵守用户“不修改代码”的要求，
仅以 Git 注释标签 `v2.12.0` 标识现有源码快照；平台自报仍为 2.11.0，探针源码声明仍为 3.5.0。
本次不覆盖同名探针包、不重建镜像、不升级真实主机；后续发布若更新探针包，必须先分配新版本，
同步 `probe/probe.py`、`backend/app/core/config.py`、`scripts/build_probe_packages.py` 的版本再打包。
详见 [发布记录](releases/v2.12.0.md)。


## v2.13.0 发布（2026-09-20）

`refactor/data-asset-boundaries` 的 30 个提交合并回 `develop` 后发布：平台版本升到 2.13.0
（`backend/app/main.py`、`frontend/package.json`、`frontend/package-lock.json`），探针源码声明保持 3.5.0
（本版未改探针代码，不重建也不覆盖同名分发包），数据库迁移保持 `0015_alert_hits`。本机已重建 backend /
worker / beat / deployment-worker 与 frontend 镜像并切换容器，运行栈自报 2.13.0。
本次是纯结构调整，不新增功能、不改判定逻辑、不动历史数据；详见 [发布记录](releases/v2.13.0.md)。


## v2.14.0 发布（2026-09-20）

本批改动（统一规则源、命中原文回传、共享文件来源、数据库直连盘点）在工作树内完成：平台版本升到 2.14.0
（`backend/app/main.py`、`frontend/package.json` 与 lock），探针版本升到 3.6.0
（`probe/probe.py`、`backend/app/core/config.py`、`scripts/build_probe_packages.py` 与 `.env`/`.env.example`
同步；本版改了探针源码，已重建并覆盖 `probe_packages/probe-3.6.0/`），迁移新增
`0016_database_connections` 与 `0017_file_sources`，head = `0017_file_sources`。本机已重建 backend /
worker / beat / deployment-worker 与 frontend 镜像并切换容器，运行栈自报 2.14.0、`/api/v1/health` 全绿。
同时产出 x86_64 Linux（银河麒麟 V10 SP1 / Ubuntu 22.04 LTS）离线一键部署包，见
[x86_64 Linux 离线交付包](offline-package.md)，
版本细节见 [发布记录](releases/v2.14.0.md)。本批未对任何真实主机升级探针、未创建 Git 标签。


## v2.14.0 交付更新（探针 3.7.0，2026-09-21）

同一平台版本（2.14.0）下的交付更新：探针升到 **3.7.0**——分发包自带私有 CPython 3.11、全部 Python 依赖、
`dumpcap`/`tcpdump` 与 ELF 库闭包、私有加载器与 CA 证书，目标机不再需要 Python、pip、apt、wheel 或抓包工具；
平台侧预检（`backend/app/deployment/{preflight,runtime}.py`）改用同一运行时探测目标机。本轮收尾把
「下发后不依赖目标环境」落进实现与验收：`ExecStart` 固定指向 `probe/run-probe.sh`（只用 shell 内建命令定位
自身目录、自设 `PATH`、固定 `PYTHONUTF8=1`/`PYTHONIOENCODING=utf-8`），`install.sh` 安装前一次性检查主机
工具，`runtime_check.py` 校验运行时布局并断言解释器来自包内 `python/`。采集身份不变（`dstprobe` +
`CAP_NET_RAW`/`CAP_NET_ADMIN`/`CAP_DAC_READ_SEARCH`，不提权到 root）。

- 版本声明：探针 3.7.0（`probe/probe.py`、`backend/app/core/config.py`、`scripts/build_probe_packages.py`、
  `.env.example`）；平台自报仍为 2.14.0；迁移 head 保持 `0017_file_sources`（无新迁移）。
- 分发包：`probe_packages/probe-3.7.0/{amd64,arm64}`（amd64 sha256 `0ac9fe87…`、arm64 `027ad503…`）；
  镜像另打 `dst-toolbox/*:2.14.0-probe3.7.0` 标签，供已部署实例就地升级。
- 离线交付包：`dst-toolbox-2.14.0-linux-x86_64.tar.gz`（`deploy_rev` **r5**，sha256 `42adc92d…`）。
- 本次发布创建 Git 注释标签 **v2.14.0**（2026-09-20 的 2.14.0 快照当时未打标签）。
- 未做：真机（192.168.191.130）探针就地升级、arm64 原生抓包复验、探针 `/tmp` 的 `PrivateTmp` 隔离。
