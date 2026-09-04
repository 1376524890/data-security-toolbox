# 数据安全工具箱 · 使用教程

> 适用版本：`develop`（v1.0）
> 更新日期：2026-09-04
> 面向：企业内网 / 离线环境的数据安全检测与安全审计操作员、运维、安全分析人员

## 0. 系统概览

本平台是一套统一插件化的数据安全检测与审计平台。核心链路为：

```
探针 Probe（受监控主机采集/抓包/资产/文件）
        │ 认证上传（X-Probe-ID / X-Probe-Token）
        ▼
后端分析平台 FastAPI + Celery + PostgreSQL + Redis
        │ tshark / Zeek / Suricata / Presidio / MISP / osquery / Wazuh / OpenSCAP
        ▼
检测结果 DetectionResult → 事件关联 Incident → 告警 Alert
        ▼
Vue 管理控制台（前端） + 报告（HTML / PDF / CSV）
```

**能力概览**：数据资产识别、文件元数据分析、商用密码算法评估、PCAP 协议分析、流量分析、威胁情报、离线资源中心、安全审计 / 任务 / 报告 / 管理控制台。

## 1. 当前服务状态（实测）

当前单机 Docker Compose 栈已启动且全部健康：

| 服务 | 容器 | 状态 | 访问方式 |
|------|------|------|----------|
| 前端（nginx 代理 `/api/`） | `0901--frontend-1` | Up (healthy) | `http://localhost:8080` |
| 后端 API（FastAPI） | `0901--backend-1` | Up (healthy) | `http://localhost:8000` |
| 异步分析 Worker | `0901--worker-1` | Up (healthy) | 内部 |
| 定时任务 Beat | `0901--beat-1` | Up | 内部 |
| Celery 监控 Flower | `0901--flower-1` | Up | 内部 `:5555`（仅 expose，未映射宿主机） |
| PostgreSQL | `0901--postgres-1` | Up (healthy) | `:5432`（容器网络） |
| Redis | `0901--redis-1` | Up (healthy) | `:6379`（容器网络） |

后端健康接口返回：`status=ok`，数据库/Redis/Celery 正常，分析引擎可用：

- **tshark** `4.4.18` ✅
- **Zeek** `8.2.2` ✅
- **Suricata** `7.0.10` ✅

当前平台已积累数据（截至 2026-09-04）：资产 4、文件 30、PCAP 184、异常 190、任务 216、事件 3、告警 23、高风险管理项 203、敏感数据资产 5；会话流 12,864 条。探针注册 2 台，当前均为 **离线**（`last_seen` 2026-09-03），需重新启动探针才会恢复在线。

> 说明：Flower 容器仅 `expose 5555`，宿主机 `localhost:5555` 不可直达。如需浏览器访问，可在 `docker-compose.yml` 的 `flower` 服务下补充 `ports: ["5555:5555"]` 后 `docker compose up -d flower`。

## 2. 访问与登录

### 2.1 访问入口

- **管理台（推荐）**：`http://localhost:8080`
- **API 文档（OpenAPI）**：`http://localhost:8000/docs`
- **后端 API 根**：`http://localhost:8000/api/v1`

### 2.2 登录

管理台登录使用 `.env` 中的账号：

- 用户名：`ADMIN_USERNAME`（默认 `admin`）
- 密码：`ADMIN_PASSWORD`（`.env` 中已配置）

登录为 Cookie 会话（非 Bearer Token）。本地 HTTP 环境下 `COOKIE_SECURE=false`，生产 HTTPS 部署请设为 `true`。

### 2.3 关键配置（`.env`）

部署前必须配置强口令：

```bash
POSTGRES_PASSWORD=强口令
SECRET_KEY=至少32位随机字符
ADMIN_PASSWORD=强管理员口令
PROBE_BOOTSTRAP_TOKEN=探针注册令牌
```

可选：`HTTP_PORT`（默认 8080）、`PCAP_RETENTION_DAYS`、`PCAP_STORAGE_MAX_GB`、`QUEUE_PENDING_MAX`、`PRESIDIO_ENABLED`（Presidio 中文 PII 模型，默认关闭以避免首调下载数百 MB 模型阻塞 worker）。

## 3. 核心使用流程

按数据来源分为四条路径，可按需选择。

### 3.1 路径 A：上传 PCAP 做网络协议与流量分析（Web）

1. 打开管理台 `http://localhost:8080`，登录。
2. 进入 **网络分析 → PCAP 工作台**。
3. 上传 `.pcap` / `.pcapng` 文件。
4. 系统自动创建分析任务，后台用 tshark 解析并跑规则引擎。
5. 在 **PCAP 工作台** 查看协议分布、会话流、五元组、**数据包分层树 + 原始字节**、TCP 流跟踪（stream follow）。
6. 在 **会话流探索**、**协议分析**、**实时流量** 查看全局视角。

### 3.2 路径 B：部署探针，自动采集受监控主机

探针部署在**被监控主机**上，负责抓包、资产端口采集与目标文件采集。需 Python 3.11+、`requests`、`psutil`，以及 `dumpcap`（优先）或 `tcpdump`。

```bash
# 1. 安装探针（创建 dstprobe 用户、systemd 服务、配置目录）
cd probe && sudo ./install.sh

# 2. 编辑配置
sudo vi /etc/data-security-toolbox/probe.toml
```

核心配置项（`probe.toml`）：

```toml
[server]
url = "http://<平台IP>:8000"        # 平台后端地址
verify_tls = false

[capture]
interface = "eth0"                  # 抓包网卡
segment_seconds = 30

[agent]
bootstrap_token = "<PROBE_BOOTSTRAP_TOKEN>"
ports = [22, 80, 443, 8080, 6379, 3306]   # 资产端口探测
paths = ["/var/lib/dst-data"]             # 目标文件目录（可选）
file_interval_seconds = 0                 # >0 时采集并上传目标文件内容
```

```bash
# 3. 启动 / 重启
sudo systemctl restart data-security-toolbox-probe
```

**探针行为要点**：

- 首次注册返回 `probe_id + token`，写入 `/etc/data-security-toolbox/probe.identity.json`（0600），**重启不轮换**。
- 抓包分片原子落盘 spool，认证上传 `/api/v1/pcaps/upload`，失败指数退避；spool 满则降级保留证据。
- 心跳上报 CPU / 内存 / 捕获速率 / 上传状态；`asset_loop` 上报开放端口 + banner；`file_loop` 上传目标文件内容触发敏感检测。
- 以 root 手动运行时，dumpcap 会降权，spool 目录需可写（`chmod 777` 或由运行用户属主）。生产用 `dstprobe` + `CAP_NET_RAW` 时由属主解决。

> 手动运行示例：`python3 probe.py --config /etc/data-security-toolbox/probe.toml`

### 3.3 路径 C：目标文件上传与敏感数据检测

配置探针 `agent.paths` 并设置 `file_interval_seconds > 0` 后，探针会自动上传目标文件内容至 `/api/v1/files/upload`，后端 `data_engine` 对真实字节做 PII / 密钥 / YARA 检测。

也可直接在管理台 **资产与数据安全 → 文件分析** 上传单个文件手动分析。

实测可检出的示例规则：

- `DATA_SECRET_001`（Critical，密钥/口令）
- `DATA_PII_001`（High，身份证/手机号/银行卡/邮箱）
- `DATA_YARA_001`（High，恶意文件特征，如 eicar）

### 3.4 路径 D：资产分析与弱口令 / 弱认证检测

- 探针 `asset_loop` 上报开放端口与 banner。
- 后端 `asset_engine` 分析服务指纹。
- 对含 `noauth` / `Authentication not required` banner 的 Redis / MySQL 命中 `ASSET_DB_WEAK_AUTH_001`（High）。
- 管理台 **资产中心 / 数据资产 / 资产关系图** 查看结果。

## 4. 管理控制台功能导航

| 分组 | 页面 | 用途 |
|------|------|------|
| 总览 | 安全驾驶舱 | 仪表盘：资产/风险/事件/告警/趋势 |
| 安全运营 | 告警中心 | 告警列表、详情、关联资产/IOC/数据资产、处置 |
| 安全运营 | 安全事件中心 | 按时间/资产/IOC/攻击链聚合的 Incident |
| 安全运营 | 检测中心 | 全部检测结果（DetectionResult） |
| 安全运营 | 风险分析 | 风险评分、等级、趋势 |
| 网络分析 | PCAP 工作台 | 上传/解析/协议树/原始字节 |
| 网络分析 | 实时流量 | 探针心跳驱动的实时指标 |
| 网络分析 | 会话流探索 | 五元组会话流、TCP 流跟踪 |
| 网络分析 | 协议分析 | 全局协议分布 |
| 资产与数据安全 | 资产中心 | IT 资产、风险等级、漏洞列表 |
| 资产与数据安全 | 数据资产 | 敏感数据分类 |
| 资产与数据安全 | 敏感发现 | 敏感类目聚合（PII/密钥/YARA） |
| 资产与数据安全 | 文件分析 | 上传文件元数据 + 敏感检测 |
| 威胁情报 | IOC 情报 / CVE 漏洞 / 检测规则 / 离线资源 | 规则、IOC、CVE、模型导入与版本管理 |
| 安全引擎 | Zeek / Suricata / Sigma / Wazuh / osquery / OpenSCAP | 外部引擎状态与日志解析 |
| 运维管理 | 探针管理 / 任务中心 / 健康状态 / 报告中心 | 探针、任务、健康、报告 |
| 工具 | 算法评估 | 商用密码应用安全性评估（GB/T 39786）、代码算法时间复杂度分析（前端自包含） |

## 5. 关键 API 速查（`/api/v1`）

### 认证
- `POST /auth/login`、`GET /auth/me`、`POST /auth/logout`

### 探针
- `POST /probes/register`（Header：`X-Probe-Bootstrap-Token`）
- `POST /probes/{id}/heartbeat`、`POST /probes/{id}/analyze`
- `GET /probes`、`GET /probes/{id}/metrics`、`GET /probes/{id}/tasks`

### 上传与分析
- `POST /pcaps/upload`（`multipart/form-data`，字段 `file`，可选 `probe_id`、`metadata_json`）
- `POST /files/upload`、`POST /files/{id}/analyze`
- `POST /pcaps/{id}/analyze`
- `POST /tasks`、`GET /tasks`、`GET /tasks/{id}`

### PCAP 深入分析
- `GET /pcaps/{id}/packets/{packet_id}`（原始字节 + 协议树）
- `GET /pcaps/{id}/streams/{stream_id}`（TCP 流 ASCII + Hex）
- `GET /pcaps/{id}/flows`、`/protocols`、`/traffic`、`/dns`、`/http`、`/tls`、`/files`、`/anomalies`、`/alerts`

### 全局数据
- `GET /flows`、`GET /protocols`、`GET /network/live`
- `GET /detections`、`GET /alerts`、`GET /alerts/stream`（SSE）、`GET /incidents`
- `GET /sensitive/findings`、`GET /rules`、`GET /assets`、`GET /data/assets`
- `GET /dashboard/summary`、`/risk-trend`、`/incident-trend`、`/severity`、`/engines`、`/sensitive-data`

### 报告 / 审计 / 集成
- `POST /reports/generate`、`GET /reports`、`GET /reports/{id}/download`
- `POST /audit/logs`、`GET /audit/summary`
- `GET /engine/registry`、`GET /integrations`、`POST /integrations/{name}/analyze`
- `POST /integrations/offline/upload`、`GET /offline/resources`、`GET /offline/cves`

所有列表接口统一分页 `{ items, page, page_size, total }`。

### 上传 PCAP 示例（curl）
```bash
curl -s -b cookies.txt -X POST http://localhost:8000/api/v1/pcaps/upload \
  -F "file=@/path/to/capture.pcapng" \
  -F "probe_id=1" \
  -F 'metadata_json={"interface":"eth0"}'
```

## 6. 生成报告

1. 在 **运维管理 → 报告中心** 选择检测 / 事件 / 风险范围。
2. 点击生成，异步任务产出报告。
3. 在报告中心下载 HTML / PDF / CSV 报告。
4. 也可通过 `POST /api/v1/reports/generate` 与 `GET /api/v1/reports/{id}/download` 用 API 生成。

## 7. 离线部署

在线环境准备离线包：
```bash
python scripts/offline_bundle.py
```

目标内网服务器：
```bash
docker load < security-toolbox-images.tar
docker compose up -d
docker compose exec backend alembic upgrade head
docker compose exec backend python scripts/seed.py
```

启动集成组件（Zeek / Suricata / MISP / Wazuh / osquery / OpenSCAP）：
```bash
docker compose -f docker-compose.yml -f docker-compose.integrations.yml --profile integrations up -d
```

导入离线规则 / IOC / CVE / 模型包：
```bash
docker compose exec backend python -c \
  "from app.core.database import SessionLocal; from app.integrations.offline_manager import import_offline_path; import pathlib; db=SessionLocal(); print(import_offline_path(db, pathlib.Path('/app/data/offline'), resource_type=None, name='bundle', version='1.0').to_dict()); db.close()"
```

## 8. 测试与验收

- 后端单测：`cd backend && python -m pytest -q`
- 前端静态检查 + 构建：`cd frontend && npm ci && npm test && npx vue-tsc --noEmit && npm run build`
- 端到端实测报告（攻击仿真、敏感数据、弱口令、探针实时捕获）：见 `docs/acceptance_test_report.md`
- 实时检测演示脚本：`tools/e2e/live_detection_demo.sh`

## 9. 常见问题 / 已知边界

- **Flower 无法访问**：仅 `expose 5555`，需在 compose 加 `ports: ["5555:5555"]` 或改用容器网络访问。
- **探针离线**：重启探针进程 / systemd 服务后恢复在线；`last_seen` 超时会标记离线。
- **探针心跳覆盖**：多循环（heartbeat/asset/file）相互覆盖 `probe.extra`，`/probes/{id}/metrics` 的 `capture_tool/cpu` 可能为空（已知遗留）。
- **HTTPS 解密未实现**：无 SSLKEYLOGFILE/密钥日志，仅采集 TLS 握手元数据（SNI/cipher/JA3）。
- **MD5 缺失**：探针计算 SHA256，后端 FileRecord 未存 md5。
- **队列背压**：高流量接口会触发后端 429（`QUEUE_PENDING_MAX` / `QUEUE_OLDEST_PENDING_SECONDS`），按目标流量调整参数。
- **Presidio 模型**：首次调用会下载 spaCy 中文模型（数百 MB），建议按需开启并预置模型。
