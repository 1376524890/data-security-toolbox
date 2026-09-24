# 数据安全监测检测工具箱

面向企业内网（含离线）环境的数据安全检测与安全审计综合平台。统一插件化检测引擎：`engine/core` + 资产/协议/流量/数据/风险/合规/威胁情报引擎，并通过 `Integration Adapter Layer` 接入 Zeek、Suricata、Presidio、MISP、Wazuh/osquery、OpenSCAP，检测结果统一输出 `DetectionResult`。

## 能力

- **数据资产识别**：主机、IP、服务、数据库资产、敏感数据分类、资产关系与风险等级
- **元数据分析**：JPG/PNG/PDF/DOCX 元数据、文件类型、SHA256、隐藏信息检测
- **OCR 与公文识别**：图片与扫描版 PDF 经 tesseract(`chi_sim`)+pdftoppm 识别文字后进入敏感数据检测，并按「版式红头 × 公文文字」判定红头文件/公文、按 `密级★期限` 等标志判定涉密文件（`DATA_CLASSIFIED_001` / `DATA_REDHEAD_001`），覆盖率随资产行上报
- **主动网络扫描**：`POST /api/v1/scan` 触发 nmap 主动发现（`-sn`）与主机服务/版本枚举（`-sV`），把扫描结果写入资产并进入资产/合规/威胁情报(CVE)流水线；前端「资产中心」提供扫描入口
- **探针侧资产扫描**：在受监控网络内执行显式授权、有主机/端口/并发/时长上限的 TCP connect 清点，支持管理端下发任务与断线后幂等回传
- **威胁情报源**：本地 IOC 导入导出与启停，支持 Feodo Tracker、URLhaus 和服务端配置的自建 JSON/CSV 情报源
- **网络 DLP**：旁路重组明文 TCP/HTTP，检测敏感字段、关键词和文件 SHA256 指纹，保存脱敏证据与覆盖范围；不在线阻断或解密 HTTPS
- **算法评估**：商用密码应用安全性评估（GB/T 39786）、代码算法时间复杂度分析；商用密码评估支持**从探针自动识别并填充**（`GET /api/v1/crypto/probe-profile`），依据探针采集的服务 banner 与 TLS 握手自动填充算法/套件/协议/密钥长度，并识别无认证/弱口令等密码风险后评估
- **协议分析**：PCAP/PCAPNG 上传、tshark/dpkt 解析、协议分布、五元组、会话、**数据包分层树 + 原始字节**、TCP 流跟踪
- **流量分析**：趋势、TopN、协议分布、主机行为画像、异常标记、实时指标
- **外部引擎**：Zeek、Suricata 日志自动解析；tshark 为核心解析器
- **集成适配器**：Zeek JSON/TAB、Suricata eve.json、Presidio 中文 PII、MISP IOC、osquery/Wazuh、OpenSCAP
- **事件关联**：`incident_engine` 按时间、资产、IOC、攻击链聚合 Finding 为 Incident
- **离线资源中心**：规则、IOC、CVE、模型安全导入与版本管理
- **安全审计 / 任务 / 报告 / 管理控制台**：HTML/PDF/CSV 报告、异步任务、探针管理、威胁情报、离线资源

## 板块功能总览

| 板块 | 入口 | 功能 |
|---|---|---|
| 安全态势 | 仪表盘 | 风险/事件/严重度/引擎/敏感数据分布总览 |
| 安全调查 | 安全事件、检测结果、风险分析 | 检测发现、Incident 聚合、ATT&CK 映射、手工关联 |
| 资产与数据 | IT资产、数据资产、资产关系图、文件分析、敏感发现 | 资产识别/分类/风险、敏感数据(PII/密钥)、元数据、OCR 与红头/涉密判定 |
| 网络分析 | PCAP分析、会话流探索、协议分析、实时流量 | tshark 解析、协议树、TCP 流、异常/端口扫描 |
| 威胁与检测 | 威胁情报、检测组件、检测规则、安全审计、算法评估 | IOC/CVE、规则驱动检测、Sigma、商用密码评估 |
| 运行管理 | 任务中心、探针管理、报告中心、健康中心 | 异步任务、探针生命周期、报告生成、组件健康 |
| 系统 | 离线资源 | 规则/IOC/CVE/模型离线导入与版本管理 |
| 网络扫描（新增） | 资产中心 →「网络扫描」 | nmap 主动发现+服务枚举，结果入资产并评估 |

## 架构

```
Probe Agent(采集) -> 上传文件/资产/PCAP -> Celery 任务 -> 后端分析服务 -> PostgreSQL -> 前端展示 -> 报告
```

- **Probe Agent**：单进程、低资源，仅负责采集、本地 spool、认证上传、心跳与轻量资产/文件清单。
- **Backend Analysis Platform**：FastAPI + Celery + PostgreSQL + Redis，负责解析、检测、调度、存储、报告。
- **Vue Management Console**：Vue 3 + Element Plus + ECharts。

## 快速开始（在线/单机）

### 1. 准备

```bash
cp .env.example .env
# 必须设置强口令：SECRET_KEY(>=32字符)、ADMIN_PASSWORD、POSTGRES_PASSWORD、PROBE_BOOTSTRAP_TOKEN
```

### 2. 构建并启动

```bash
docker compose build
docker compose up -d
docker compose exec backend python scripts/seed.py
```

访问 `http://localhost:8080`（前端，nginx 代理 `/api/` 到后端 `:8000`）。后端 API 也直接暴露于 `:8000`（供探针访问）。

> 说明：
> - 后端容器启动时自动执行 `alembic upgrade head` 建表（迁移已做幂等处理，可安全重建）。
> - `COOKIE_SECURE=false`（本地 HTTP）；生产 HTTPS 部署请设 `true`。
> - `PRESIDIO_ENABLED=false` 关闭 Presidio 模型下载（避免首次调用下载数百 MB spaCy 模型阻塞 worker）；需要 Presidio 中文 PII 时设为 `true` 并预置模型。

### 3. 集成组件（可选）

```bash
docker compose -f docker-compose.yml -f docker-compose.integrations.yml --profile integrations up -d
```

### 4. 跨平台 / 跨架构部署

本套 compose 与镜像已做架构自适应，**无需手动指定 `platform`**：

- **Linux x86_64 / arm64**：`docker compose build && docker compose up -d` 直接构建原生架构。后端 Dockerfile 通过 `dpkg --print-architecture` 自动识别 amd64/arm64：
  - Zeek 运行时库按架构拷贝（amd64 → `x86_64-linux-gnu`，arm64 → `aarch64-linux-gnu`），并用 `LD_LIBRARY_PATH` 指向，不覆盖系统库。
  - nuclei 主动扫描器按架构下载对应二进制（`linux_amd64` / `linux_arm64`）。
- **Windows（Docker Desktop，WSL2 后端）**：在 Windows 上以 Linux 容器方式运行，原生支持 x86_64。请确保 Docker Desktop 使用 WSL2 后端（默认），并在 PowerShell / WSL 中执行上述命令。相对路径挂载（`./data_security_toolbox_manual_testpack`）与 `docker compose` 均兼容。
- **可选集成（wazuh / misp）仅发布 amd64**：在 arm64 主机上运行会走 QEMU 模拟（明显变慢），x86_64 / Windows 则原生运行。若 ARM 上不需要，可跳过 `--profile integrations`。

> 说明：镜像本身为多架构（postgres/redis/node/nginx/flower 均含 amd64+arm64），构建时自动选择与宿主机一致的架构。

## 探针部署与运行

探针部署在**受监控主机**，负责抓包、资产采集与目标文件采集。**探针 3.7.0 起分发包自带运行时**（私有 CPython 3.11、`requests`/`psutil` 等依赖、`dumpcap`（优先）/`tcpdump` 与 ELF 库闭包、私有加载器与 CA），目标机**不需要 Python、pip、apt、wheel 或抓包工具**，也不用改 `ExecStart`（主机只需 systemd 与 `tar`/`useradd`/`chown` 等基础工具，启动脚本自带 `PATH` 与 UTF-8 环境）；`install.sh` 先用自带解释器校验运行时（架构、解释器版本、依赖、抓包工具、可选平台连通性、archive sha256），通过后才停服务并原子替换 `/opt/data-security-toolbox/runtime`，`probe.toml`/`probe.token`/spool/rules/cache 全部保留——重跑即升级、换旧包重跑即回退。平台侧探针部署预检也用这同一个运行时探测目标机（`app/deployment/{preflight,runtime}.py`），不再要求主机 `python3 >= 3.11` 或预装抓包工具。采集身份不变（`dstprobe` + `CAP_NET_RAW`/`CAP_NET_ADMIN`/`CAP_DAC_READ_SEARCH`，不提权到 root），读不到的目录按覆盖缺口如实上报。

```bash
# 1. 安装探针（创建 dstprobe 用户、systemd 服务、配置目录）
cd probe && sudo ./install.sh

# 2. 编辑配置
sudo vi /etc/data-security-toolbox/probe.toml
#    [server] url = "http://<平台IP>:8000" verify_tls=false
#    [capture] interface = "<网卡>" segment_seconds = 30
#    [agent] bootstrap_token = "<PROBE_BOOTSTRAP_TOKEN>"
#            ports = [22,80,443,8080,6379,3306]
#            paths = ["/var/lib/dst-data"]  # 目标文件目录（可选）
#            file_interval_seconds = 0      # >0 时采集并上传目标文件内容

# 3. 启动/重启
sudo systemctl restart data-security-toolbox-probe
```

探针行为：
- 首次注册返回 `probe_id + token`，写入 `/etc/data-security-toolbox/probe.identity.json`(0600)，**重启不轮换**。
- 抓包分片原子落盘 spool，认证上传 `/api/v1/pcaps/upload`，失败指数退避、spool 满则降级但保留证据。
- 心跳上报 CPU/内存/捕获速率/上传状态；`asset_loop` 上报开放端口 + banner；`file_loop` 上传目标文件内容触发敏感检测。

> 以 root 手动运行时，dumpcap 会降权，spool 目录需可写（`chmod 777` 或由运行用户属主）；生产用 `dstprobe` + `CAP_NET_RAW` 时由属主解决。

## 管理控制台导航

- **安全态势**：总览
- **安全调查**：安全事件、检测结果、风险分析
- **资产与数据**：IT资产、数据资产、资产关系图、文件分析、敏感发现
- **网络分析**：PCAP分析、会话流探索、协议分析、实时流量
- **威胁与检测**：威胁情报、检测组件、检测规则、安全审计、算法评估
- **运行管理**：任务中心、探针管理、报告中心、健康中心
- **系统**：离线资源

## 关键 API（`/api/v1`）

- 认证：`POST /auth/login`、`GET /auth/me`
- 探针：`POST /probes/register`、`POST /probes/{id}/heartbeat`、`GET /probes/{id}/metrics`
- 上传：`POST /pcaps/upload`、`POST /files/upload`
- 分析：`POST /pcaps/{id}/analyze`、`POST /files/{id}/analyze`、`POST /probes/{id}/analyze`
- PCAP：`GET /pcaps/{id}/packets/{pid}`（原始字节+协议树）、`/streams/{sid}`（TCP 流）、`/dns`、`/http`、`/tls`、`/files`
- 全局：`GET /flows`、`/protocols`、`/network/live`
- 数据安全：`GET /sensitive/findings`
- 检测/事件/告警：`GET /detections`、`/incidents`、`/alerts`、`/alerts/stream`（SSE）
- 规则：`GET /rules`、`/offline/resources`
- 仪表盘：`GET /dashboard/summary`、`/risk-trend`、`/incident-trend`、`/severity`、`/engines`、`/sensitive-data`

所有列表接口统一分页 `{ items, page, page_size, total }`。

## 测试

```bash
# 后端
cd backend && python -m pytest -q

# 前端（静态检查 + 构建）
cd frontend && npm ci && npm test && npx vue-tsc --noEmit && npm run build

# 端到端实测报告（含攻击仿真、敏感数据、弱口令、探针实时捕获）
# 见 docs/acceptance_test_report.md
```

## 离线部署

交付包（arm64 / aarch64 Linux）解包后**一条命令**跑完部署，全部参数集中在 `deploy/deploy.conf`：

```bash
tar -xzf dst-toolbox-3.0.0-linux-arm64.tar.gz && cd dst-toolbox-3.0.0-linux-arm64
sudo ./deploy.sh                 # 载入镜像 → 生成 .env → 起容器 → 等健康
sudo ./deploy.sh --dry-run       # 只看会写入的 .env，不动系统
sudo ./undeploy.sh               # 停栈，数据保留
```

目标机只需要 Docker Engine 20.10+ 与 `docker compose` v2，不需要外网、Python、Node 或抓包工具。
说明见 `deploy/README-离线部署.md`，发布细节见 [docs/releases/v3.0.0.md](docs/releases/v3.0.0.md)。

在构建机上线准备（需要外网；本机必须用 legacy builder，`docker compose build` 会卡在 buildx）：

```bash
DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target api             -t source-backend:latest .
DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target analysis-worker -t source-worker:latest  .
DOCKER_BUILDKIT=0 docker build -t source-frontend:latest ./frontend --no-cache
python scripts/offline_bundle.py --save          # 重出镜像归档
python scripts/make_offline_release.py           # 重出交付包
```

手工路径（不使用 `deploy.sh` 时）：

```bash
docker load < dist-offline/security-toolbox-images.tar
docker compose up -d --no-build --pull never     # 结构迁移随 API 容器启动自动执行
docker compose exec backend python scripts/seed.py
```

离线资源（规则/IOC/CVE/模型）通过 `POST /api/v1/integrations/offline/upload` 安全导入，不使用任意路径。

## 已知边界 / 限制

- **HTTPS 解密**：未实现（无 SSLKEYLOGFILE/密钥日志），仅采集 TLS 握手元数据（SNI/cipher/JA3）。
- **MD5**：探针计算 SHA256（`file_records` 含 md5 字段，后端 FileRecord 未存 md5）。
- **队列背压**：高流量接口会触发后端 429（`QUEUE_PENDING_MAX` / `QUEUE_OLDEST_PENDING_SECONDS`），按目标流量调整。
- **探针心跳覆盖**：多循环 heartbeat 相互覆盖 `probe.extra`，metrics 的 capture_tool/cpu 可能为空（建议后端合并 metadata）。

## 分支与版本

见 [docs/versioning.md](docs/versioning.md)。
