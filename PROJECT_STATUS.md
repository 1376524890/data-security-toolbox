# Project Status

> 项目整体状态快照。长期稳定信息见 `AGENTS.md`，当前任务见 `TASK.md`，架构见 `docs/architecture.md`。
> 数据均为实测，采集时间：2026-09-17。

## 当前版本

| 项 | 值 | 来源 |
| --- | --- | --- |
| 平台 | 2.10.0 | `backend/app/main.py`（FastAPI version）、`frontend/package.json` |
| 探针 | 3.5.0 | `probe/probe.py:AGENT_VERSION`、`backend/app/core/config.py:probe_agent_version` |
| 数据库迁移 | `0014_probe_removal (head)` | `alembic current` |
| 分支 / 最新提交 | `develop` / `e815a54` | `git log --oneline` |
| 工作区 | **有未提交改动**（3 个后端文件，见 `TASK.md`） | `git status` |
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

1. 后端 5 个历史遗留失败用例（与当前改动无关，见「测试状态」）。
2. 资产详情「关联事件」曾长期为空：`incident_engine._asset_keys()` 读不到情报引擎的嵌套资产、流量引擎的 `src/dst`
   与规则引擎的 `metrics` 键，且只记录单一展示标签。**修复代码已写，未验证**（见 `TASK.md`）。
3. 资产详情「IOC」曾长期为空：联动查询未读 `matched_iocs`，且 IOC 库本身只有 1 条真实指标。**部分修复，未验证**。
4. 事件标题残留旧复合标签（如 `多事件关联：192.168.191.168:...:telnet:23`），待归属重算后端到端刷新。

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
| detection_findings | 809 | incidents | 53 |
| alerts | 115 | pcaps | 1,658 |
| flows | 31,235 | tasks | 1,686 |
| reports | 2 | rules | 146 |
| local_cves | 394,371 | iocs | **1** |
| probes | 1 | audit_logs | **0** |
| vulnerabilities | **0** | graph_relations | 1,018 |

要点：

- 资产 214 条中有 200 条是 `192.168.191.168` 的 service 级资产（端口扫描真实产物），非脏数据。
- 数据资产 447 条全部属于探针主机 `192.168.191.130`（真实采集，`extra.host`）。
- 严重度分布：High 794 / Medium 1（无 Critical、Low）。
- **确认库内无测试数据**：`GET /api/v1/test/status` → `present=false`。

## API 状态

- OpenAPI 实测：**139 个路径 / 153 个操作**，前缀 `/api/v1`。
- 路由按域拆分：`api/v1.py`（主体）、`extensions.py`、`data_catalog.py`、`deployments.py`、
  `libraries.py`、`profiles.py`、`rulesets.py`。
- 列表统一 `page` / `page_size` → `{items, total, page, page_size}`。
- 认证：控制台会话 Cookie / Bearer；探针 `X-Probe-ID` + `X-Probe-Token`。
- 上一轮实测 46 个演示相关端点全部 200（`e815a54` 之后）。

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
- 上一轮基线：全量 520 个用例，仅 5 个已知失败。

## Docker 状态

运行中的服务（`docker compose -p source`）：`postgres`、`redis`、`backend`、`worker`、`beat`、
`deployment-worker`、`frontend`、`flower`。另有独立的 `openaev-*` 集成栈在跑（第三方靶场/系统，非本项目服务）。

端口：后端 8000，控制台 `${HTTP_PORT}`=8088。

构建注意：必须 `DOCKER_BUILDKIT=0` 走 legacy builder，否则永久卡住（见 `AGENTS.md`）。

## 测试状态

| 套件 | 命令 | 基线 |
| --- | --- | --- |
| 后端全量 | `docker exec source-backend-1 python -m pytest -q` | 520 用例，5 个历史失败 |
| 前端单测 | `docker exec source-frontend-1 npx vitest run` | 31/31 通过 |
| 前端类型 | `docker exec source-frontend-1 npx vue-tsc --noEmit` | 干净 |

5 个历史失败用例：`tests/engine/test_protocol_engine.py::test_protocol_engine_runs_on_fixture`、
`tests/probe/test_probe_identity.py::test_first_registration_persists_identity`（Windows chmod 语义）、
`tests/test_api.py::test_health`（Redis 降级）、
`tests/test_protocol_service.py::test_stream_tshark_watchdog_timeout`、
`tests/test_protocol_service.py::test_pcap_total_exceeds_index_limit`。

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

## 兼容性变更记录

| 变更 | 影响面 | 说明 |
| --- | --- | --- |
| 事件 `evidence.asset` 语义改为 IP | 前端事件中心展示、事件搜索 | 展示更短更可读；`assets` 为新增字段，不影响旧字段解析 |
| 事件 `evidence.assets` 新增 | 新增字段 | 旧数据缺该字段，查询侧已做兼容（缺失即跳过） |
| `/api/v1/protocols` 增加 `layer` 字段 | 新增字段 | 旧消费者忽略即可；`tree` 排序改为按计数倒序 |
| `/api/v1/pcap/alerts` 的 alert 项 evidence 改为命中规则的 evidence | 修复错误数据 | 原先返回告警自身元数据（id/severity/时间），非规则证据 |

禁止修改项与硬约束见 `AGENTS.md`「禁止修改的内容」。
