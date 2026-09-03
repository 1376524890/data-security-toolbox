# Data Security Toolbox

面向企业内网（含离线）环境的数据安全检测与安全审计综合平台。统一插件化检测引擎：`engine/core` + 资产/协议/流量/数据/风险/合规/威胁情报引擎，并通过 `Integration Adapter Layer` 接入 Zeek、Suricata、Presidio、MISP、Wazuh/osquery、OpenSCAP，检测结果统一输出 `DetectionResult`。

## 能力

- **数据资产识别**：主机、IP、服务、数据库资产、敏感数据分类、资产关系与风险等级
- **元数据分析**：JPG/PNG/PDF/DOCX 元数据、文件类型、SHA256、隐藏信息检测
- **算法评估**：商用密码应用安全性评估（GB/T 39786）、代码算法时间复杂度分析（前端自包含工具）
- **协议分析**：PCAP/PCAPNG 上传、tshark/dpkt 解析、协议分布、五元组、会话、**数据包分层树 + 原始字节**、TCP 流跟踪
- **流量分析**：趋势、TopN、协议分布、主机行为画像、异常标记、实时指标
- **外部引擎**：Zeek、Suricata 日志自动解析；tshark 为核心解析器
- **集成适配器**：Zeek JSON/TAB、Suricata eve.json、Presidio 中文 PII、MISP IOC、osquery/Wazuh、OpenSCAP
- **事件关联**：`incident_engine` 按时间、资产、IOC、攻击链聚合 Finding 为 Incident
- **离线资源中心**：规则、IOC、CVE、模型安全导入与版本管理
- **安全审计 / 任务 / 报告 / 管理控制台**：HTML/PDF/CSV 报告、异步任务、探针管理、威胁情报、离线资源

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

## 探针部署与运行

探针部署在**受监控主机**，负责抓包与目标文件采集。需要 Python 3.11+（`tomllib`、`datetime.UTC`）、`requests`、`psutil`，以及 `dumpcap`（优先）或 `tcpdump`。

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

```bash
# 在线准备离线包
python scripts/offline_bundle.py

# 目标内网
docker load < security-toolbox-images.tar
docker compose up -d
docker compose exec backend alembic upgrade head
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
