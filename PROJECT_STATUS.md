# Project Status

> 项目整体状态快照。长期稳定信息见 `AGENTS.md`，当前任务见 `TASK.md`，架构见 `docs/architecture.md`。
> 数据均为实测，采集时间：2026-09-17。

## 当前版本

| 项 | 值 | 来源 |
| --- | --- | --- |
| 平台 | 2.10.0 | `backend/app/main.py`（FastAPI version）、`frontend/package.json` |
| 探针 | 3.5.0 | `probe/probe.py:AGENT_VERSION`、`backend/app/core/config.py:probe_agent_version` |
| 数据库迁移 | `0014_probe_removal (head)` | `alembic current` |
| 分支 / 最新提交 | `develop` / `0cf03de` | `git log --oneline` |
| 工作区 | 干净 | `git status` |
| 远端 | `origin` = `https://github.com/1376524890/data-security-toolbox.git` | `git remote -v` |

## 已实现模块

- 探针侧：流量分段采集（tshark/dumpcap）、资产盘点、数据资产清单（只上传身份/推断列/敏感类目计数）、
  文件内容分析（哈希 + 敏感数据检测）、中心规则集下载与原子替换、心跳、受控远程扫描、
  安装/卸载（`probe/install.sh`、`probe/uninstall.sh`）。
- 服务端检测层（`app/engine/`）：资产、合规、数据、协议、风险、流量六个引擎 + 统一 `DetectionPipeline`。
- 威胁情报：`app/threat_intel`（IOC 命中 `TI_IOC_001`、本地 CVE 关联 `CVE_*`）、
  情报源接入（Feodo / URLhaus / 自建 JSON-CSV，`app/services/intelligence_service.py`）、离线情报导入。
- 关联与告警：`app/incident_engine`（多 Finding 聚合成 Incident）、告警生成/抑制/投递（Webhook、SMTP）。
- 第三方适配：`app/integrations/`（Zeek、Suricata、Presidio、MISP、osquery/Wazuh、OpenSCAP、离线包管理）。
- 平台能力：任务调度（Celery + beat）、报告生成、探针下发与回收（SSH + 事件流水 + 审计）、
  数据目录/数据对象（`data_objects` / `asset_instances`）、规则库（146 条）、本地 CVE 库（394,371 条）、操作审计（部分）。
- 前端控制台：`dashboard`、`asset`、`data-security`、`network`、`operations`、`operations-admin`、
  `threat`、`engines`、`tools` 九个业务域。

## 未实现模块 / 功能缺口

- **全量操作审计**：`audit_logs` 目前只有 2 条写入路径（`api/data_catalog.py` 的 rebuild / backfill），
  其余写操作、列表页、导出均未记录。
- **`vulnerabilities` 表无写入方**：全仓只有 `asset_detail` 读取它，当前 0 行。
  CVE 命中实际以 Finding（`rule_id = CVE_*`）形式存在，不落该表。
- **情报源无定时同步**：`beat_schedule` 五项任务中不含 `intel_sync`，只能由前端手动触发。
- **前端无情报源数据资产页**：`/intelligence/providers` 已有 UI（威胁情报 → 情报源），但 IOC 库本身仍近乎为空（见下）。

## 已知 Bug

1. 后端存在 16 个**环境相关**失败用例：镜像不含 `tests/`、`pyproject.toml`、`probe_packages/` 时必然失败，
   与代码无关（见「测试状态」的口径说明）。
2. `protocol_engine` 的 `PROTO_DNS_TUNNEL_001` 证据只有域名与报文计数、不含主机地址，
   因此该事件仍归属 `global`（当前 55 条事件中 1 条）。要归属需在 DNS 解析层保留查询源地址。
3. `iocs` 表只有 1 条真实指标：Feodo 官方 recommended 列表当前真实内容就是 1 条（`# END 1 entries`）。
   资产 IOC 页签在未命中时为空属预期，非缺陷。

已修复（`0cf03de`，已部署验证）：资产详情「关联检测 / 关联事件」长期为空、事件退化成 `global`、
多主机事件只对一台主机可见、IOC 联动不读 `matched_iocs`、findings 去重签名对流量 findings 恒为空。

## 技术债务

- ruff E501 存量约 1,000+ 处（`line-length = 100`），只约束新增代码。
- 前端无 lint/format 配置，仅靠 `vue-tsc` + `vitest`。
- `frontend/src/mocks/`（假数据适配器）与生产代码同仓，仅靠 `VITE_DEMO_MODE` 构建期开关隔离。
- 控制台顶部仍保留「测试数据 → 导入/清除测试数据」入口（`frontend/src/App.vue`），
  与「只用真实数据」的交付要求冲突，待决策是否在生产构建隐藏。
- 本机 `docker compose build` 会被挂起的 buildx 客户端卡死，必须改用 legacy builder（见 `AGENTS.md`）。

## 当前架构

详见 `docs/architecture.md`。一句话概览：

```
探针（采集/上传/心跳） --HTTPS/X-Probe-*--> FastAPI（鉴权、入库、建任务）
                                              |
                                         Redis 队列
                                              |
                        Celery worker（15 个检测/适配引擎 -> RiskEngine -> Finding/Alert/Incident）
                                              |
                                        PostgreSQL + 文件存储
                                              |
                              FastAPI 查询 API --> Vue 控制台（nginx）--> 报告
```

## 数据库状态

实测行数（`psql` 直查 `security_toolbox`）：

| 表 | 行数 | 表 | 行数 |
| --- | --- | --- | --- |
| assets | 214 | asset_instances | 205 |
| data_assets | 447 | data_objects | 245 |
| detection_findings | 815 | incidents | 55 |
| alerts | 122 | pcaps | 1,745 |
| flows | 32,356 | tasks | 1,775 |
| reports | 2 | rules | 146 |
| local_cves | 394,371 | iocs | **1** |
| probes | 1 | audit_logs | 2 |
| vulnerabilities | **0** | graph_relations | 1,018 |
| detections | 5 | detection_evidence | 3 |

要点：

- 资产 214 条中有 200 条是 `192.168.191.168` 的 service 级资产（端口扫描真实产物），非脏数据。
- 数据资产 447 条全部属于探针主机 `192.168.191.130`（真实采集，`extra.host`）。
- 严重度分布：High 794 / Medium 1（无 Critical、Low）。
- 事件归属分布（修复后）：`192.168.191.168` 28、`192.168.191.1` 15、`192.168.110.168` 6、`127.0.0.1` 3、
  `139.199.215.251` 1、`1.12.12.12` 1、`global` 1（DNS 隧道，证据本身无主机）。
- `audit_logs` 现有 2 行，均为 `incidents.rebuild_attribution`（actor=admin），
  证明维护端点按设计写审计；覆盖面仍远小于「全量操作审计」。
- `detections` / `detection_evidence`（数据对象的敏感类目明细，由 `data_object_service` 写入）与
  `detection_findings`（引擎检测结果）是两套并存模型，当前行数 5 / 3 / 815，勿混淆。
- **确认库内无测试数据**：`GET /api/v1/test/status` → `present=false`。

## API 状态

- OpenAPI 实测：**140 个路径 / 154 个操作**，前缀 `/api/v1`（较上一轮 +1：`POST /incidents/rebuild-attribution`）。
- 路由按域拆分：`api/v1.py`（主体）、`extensions.py`、`data_catalog.py`、`deployments.py`、
  `libraries.py`、`profiles.py`、`rulesets.py`。
- 列表统一 `page` / `page_size` → `{items, total, page, page_size}`。
- 认证：控制台会话 Cookie / Bearer；探针 `X-Probe-ID` + `X-Probe-Token`。
- 全量 GET 冒烟：跳过下载/流式/导出端点后共 **89 个 GET**，77 个 200；
  其余 12 个为参数/鉴权语义导致的预期非 2xx（探针专用接口无 `X-Probe-*` 返回 401；
  合成 id=1 在 `asset_instances`/`scan_profiles`/`detections` 等表不存在返回 404；
  `crypto/probe-profile`、`probes/{id}/command-status` 缺必填查询参数返回 422）。

## 前端状态

- 构建期常量隔离 mock：`VITE_DEMO_MODE=true` 才会挂 `src/mocks/adapter.ts`（`api/client.ts`），生产构建不启用。
- 页面分包：9 个业务域模块；驾驶舱、资产中心、PCAP 工作台、协议分析、事件中心、告警中心、IOC 情报、情报源、规则库等。
- 近期修复：驾驶舱环形图（统一 `severityOrder` / `severityLabels` / `severityTagColors`）、
  协议分布只显示应用层、PCAP 告警证据改用命中规则的真实 evidence。
- 单测 31/31 通过，`vue-tsc --noEmit` 干净（上一轮基线）。

## 后端状态

- FastAPI（8000，容器 healthy）+ Celery worker + beat + 独立 `deployment-worker`（探针下发/回收）。
- 检测引擎 6 个 + 情报/适配/关联三套子系统；`evidence` 中的资产身份解析本轮统一到
  `evidence_asset_keys()` / `evidence_ioc_keys()`。
- 全量基线（固定口径，见「测试状态」）：HEAD 521 用例 / 16 环境失败；当前 525 用例 / 同样 16 个失败。

## Docker 状态

运行中的服务（`docker compose -p source`）：`postgres`、`redis`、`backend`、`worker`、`beat`、
`deployment-worker`、`frontend`、`flower`。另有独立的 `openaev-*` 集成栈在跑（第三方靶场/系统，非本项目服务）。

端口：后端 8000，控制台 `${HTTP_PORT}`=8088。

构建注意：必须 `DOCKER_BUILDKIT=0` 走 legacy builder，否则永久卡住（见 `AGENTS.md`）。

## 测试状态

| 套件 | 命令 | 基线 |
| --- | --- | --- |
| 后端全量（固定口径） | 见下方 `docker run` 说明 | HEAD `e815a54` = 521 用例 / 16 失败；当前 = **525 用例 / 16 失败，失败集合逐条一致** |
| 前端单测 | `docker exec source-frontend-1 npx vitest run` | 31/31 通过 |
| 前端类型 | `docker exec source-frontend-1 npx vue-tsc --noEmit` | 干净 |

**镜像不含 `tests/`、`pyproject.toml`、`probe_packages/`**，因此 `docker exec ... pytest` 无法直接跑用例。
固定口径（HEAD 与当前改动用完全相同的命令各跑一次，再逐条比对失败集合）：

```powershell
$src = (Resolve-Path ".\00-数据安全工具箱\source").Path
docker run --rm -v "${src}\backend\app:/app/app" -v "${src}\backend\tests:/app/tests" `
  -v "${src}\backend\pyproject.toml:/app/pyproject.toml" -v "${src}\probe:/app/probe" `
  -v "${src}\shared:/app/shared" -v "${src}\probe_packages:/app/probe_packages" `
  -w /app source-backend:latest python -m pytest -q
```

该口径下的 16 个失败全部由环境缺失/降级引起，与本次改动无关：

- `tests/deployment/test_package.py` 4 个（容器内 `probe_packages` 未构建出 manifest）
- `tests/shared/test_distribution.py` 10 个（安装脚本可执行位、分发清单等依赖完整仓库布局）
- `tests/test_api.py::test_health`（无 Redis 时为 `degraded`）
- `tests/test_gap_fixes.py::test_integrations_reports_worker_zeek_suricata_capability`（无 worker 能力上报）

## 最近的重要设计决定

1. **资产身份 = IP**。事件的 `evidence.asset` 由「ip:host:service:port 复合串」改为 IP，展示标签之外另存
   `evidence.assets`（事件覆盖的全部主机），使多主机事件能被每台相关资产查到。
2. **身份解析集中一处**：`evidence_asset_keys(evidence)` / `evidence_ioc_keys(evidence)` 供事件关联、
   findings 去重、维护端点共用，避免同一份 evidence 在不同模块解读出不同资产。
3. **维护端点只重算派生数据**：历史事件的错误归属通过重算 `asset`/`assets` 修复，
   不新增、不删除事件，不改 `fingerprint`，因此不会产生重复事件。
4. **协议分布只统计应用层**：`protocol_layer()` 区分 link/network/transport/application，前端图表过滤到应用层，
   原始计数器与逐包协议树保持原样（不损失取证信息）。
5. **探针卸载的删除白名单固定**：删除目标必须来自脚本内常量，不读命令行参数、不读目标机文件，
   符号链接只删链接本身，成功后才删平台记录。
6. **交付环境禁用任何演示数据**：`POST /api/v1/test/import` 与 `VITE_DEMO_MODE` 均不得用于生产/演示环境。
7. **身份与展示分离**：`_asset_identity()` 解析用于关联的身份（嵌套资产取 `ip`），`_short_asset()` 仍是展示标签
   （`ip:service:port` 复合串）。把展示串当身份用是本次缺陷的共同根因。
8. **多主机事件同时归属多台主机**：`evidence.asset` 只是展示用的首标签，`evidence.assets` 才是成员集合，
   查询侧一律按成员判定（LIKE 只做候选过滤，Python 侧精确判定，保证 SQLite 测试与 PostgreSQL 行为一致）。

## 兼容性变更记录

| 变更 | 影响面 | 说明 |
| --- | --- | --- |
| 事件 `evidence.asset` 语义改为 IP | 前端事件中心展示、事件搜索 | 展示更短更可读；`assets` 为新增字段，不影响旧字段解析 |
| 事件 `evidence.assets` 新增 | 新增字段 | 旧数据缺该字段，查询侧已做兼容（缺失即跳过） |
| `/api/v1/protocols` 增加 `layer` 字段 | 新增字段 | 旧消费者忽略即可；`tree` 排序改为按计数倒序 |
| `/api/v1/pcap/alerts` 的 alert 项 evidence 改为命中规则的 evidence | 修复错误数据 | 原先返回告警自身元数据（id/severity/时间），非规则证据 |
| 新增 `POST /api/v1/incidents/rebuild-attribution` | 新增端点 | 只重算已有事件的 `asset`/`assets`/`stages`/`title`，不增删事件、不改 `fingerprint`；写 `audit_logs` |
| `asset_detail` 的「关联检测」匹配范围扩大 | 同一资产可能返回比以前更多的 findings | 由「只看 `evidence.asset.ip`/`evidence.ip`」扩大到所有主机拼写，实测 192.168.191.130 由 0 变 99 |

禁止修改项与硬约束见 `AGENTS.md`「禁止修改的内容」。
