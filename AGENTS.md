# AGENTS.md

本文件只保存长期稳定的信息（项目是什么、怎么开发、有哪些硬约束）。
临时任务进度看 `TASK.md`，项目整体状态看 `PROJECT_STATUS.md`，架构看 `docs/architecture.md`。

新会话开始工作前：先读这四个文件 → 再看 `git status` / `git log --oneline -10` → 最后核对真实代码。
**不要只依赖聊天历史判断项目状态。**

## 项目名称

数据安全工具箱（Data Security Toolbox）。完整仓库在 `00-数据安全工具箱/source/`，git 仓库根目录就是 `source/`。
本文档及 `TASK.md` / `PROJECT_STATUS.md` 中的相对路径均相对 `source/`。

## 项目用途

面向企业内网的数据安全检查与合规检测工具箱：在被检查主机上部署轻量探针采集流量与文件，服务端用多引擎分析，
产出资产、敏感数据资产、检测发现（Finding）、关联事件（Incident）、告警与检查报告，服务于数据安全合规检查服务交付。

## 技术栈

| 层 | 技术 |
| --- | --- |
| 后端 | Python 3.11 / FastAPI / SQLAlchemy 2.0 / Alembic / Celery / Redis / PostgreSQL 16.6 |
| 前端 | Vue 3 + TypeScript + Vite 6 + Element Plus + ECharts + Pinia + vue-router + Vue Flow |
| 探针 | 单进程 Python（`probe/probe.py`）+ systemd 单元；依赖 tshark/dumpcap 采集 |
| 部署 | Docker Compose（本地/离线两种） |
| 测试 | 后端 pytest；前端 vitest + `vue-tsc --noEmit` |

## 目录结构

```
source/
├── backend/                 # FastAPI + Celery 后端
│   ├── app/
│   │   ├── api/             # HTTP 路由（v1.py 为主体，其余按域拆分）
│   │   ├── core/            # 配置、数据库、日志等基础设施
│   │   ├── deployment/      # 探针下发/回收的状态机与记录
│   │   ├── engine/          # 检测引擎（见下）
│   │   ├── incident_engine/ # 事件关联（Finding -> Incident）
│   │   ├── integrations/    # 第三方适配器（Zeek/Suricata/MISP/离线导入等）
│   │   ├── rules/           # 规则解析与解释器
│   │   ├── services/        # 领域服务（资产/协议/情报/数据对象/报告…）
│   │   ├── threat_intel/    # 威胁情报引擎（IOC 匹配、CVE 关联）
│   │   ├── workers/         # Celery 任务
│   │   └── models.py        # 全部 SQLAlchemy 模型
│   ├── alembic/versions/    # 数据库迁移
│   └── tests/               # pytest 用例
├── frontend/                # Vue 控制台（nginx 静态托管 + /api 反代）
│   └── src/{api,modules,components,router,stores,types,utils,mocks}
├── probe/                   # 探针源码、install.sh / uninstall.sh、systemd 单元
├── shared/                  # 前后端/探针共享逻辑（scanning、sensitive_detection）
├── scripts/                 # seed.py、离线打包、E2E 脚本
├── docs/                    # 设计、部署、验收、演示文档
├── data/                    # 运行期数据（SQLite 测试库等）
└── docker-compose*.yml      # 本地 / 生产 / 集成三套编排
```

## 核心模块说明

- `app/engine/`：统一检测引擎层。所有检测器实现 `DetectionEngine.analyze(context) -> list[DetectionResult]`，
  由 `EngineRegistry` 注册、`DetectionPipeline` 调度。现有：`asset_engine`、`compliance_engine`、
  `data_engine`、`protocol_engine`、`risk_engine`、`traffic_engine`。
- `app/threat_intel/engine.py`：IOC 命中（`TI_IOC_001`）与 CVE 关联（`CVE_*`）。
- `app/incident_engine/engine.py`：把多个 Finding 按时间窗口 + 资产 + IOC 聚合成 Incident；
  对外暴露 `evidence_asset_keys(evidence)` / `evidence_ioc_keys(evidence)` 供其他模块复用同一套身份解析。
- `app/services/protocol_service.py`：PCAP/协议解析与分类（`protocol_layer` 区分链路/网络/传输/应用层）。
- `app/deployment/`：探针下发与回收（SSH 下发、状态机、事件流水、生产文件清理清单）。
- `app/workers/tasks.py`：Celery 任务入口（分析、情报同步、告警投递、探针部署）。
- `frontend/src/modules/`：控制台按业务域分包 —— `dashboard`、`asset`、`data-security`、
  `network`、`operations`、`operations-admin`、`threat`、`engines`、`tools`。

## 编码规范

- Python：ruff（`line-length = 100`，`select = ["E","F","I","B","UP"]`，`target-version = "py311"`）。
  E501 历史存量很多，只对新增/修改的代码负责，不要批量重排老文件。
- 注释写“为什么”，不写“做了什么”；修 bug 时在关键处注明根因，避免后人再踩。
- 前端没有 eslint/prettier 配置，质量靠 `npm run typecheck` + `npm test` 把关。
- 改动保持最小化：不要为了小功能大规模重构无关代码，不要顺手改文件名或变量名。

## API 规范

- 统一前缀 `/api/v1`；后端容器监听 8000，控制台由 nginx 监听容器内 80、宿主 `${HTTP_PORT}`。
- 路由按域拆分注册：`app/api/v1.py`（聚合主体，自身不再声明路径）、`data_collection.py`、`data_assets.py`、`pcaps.py`、`files.py`、`assets.py`、`incidents.py`、
  `alerts.py`、`tasks.py`、`reports.py`、`detections.py`、`engines.py`、`dashboard.py`、`probes.py`、`extensions.py`、
  `integrations.py`、`data_catalog.py`、`deployments.py`、`libraries.py`、`profiles.py`、`rules.py`、
  `auth.py`、`health.py`、`network_scan.py`、`test_data.py`、`rulesets.py`；
  跨域复用的鉴权与上传守卫放 `api/dependencies.py`，跨域复用的响应结构放 `api/*_presenter.py`。
- 列表统一用 `page` / `page_size`，返回 `{items, total, page, page_size}`（见 `app/api/pagination.py`）。
- 认证：控制台用会话 Cookie / Bearer；探针接口用 `X-Probe-ID` + `X-Probe-Token`。
- 不要随意删除已有 API、改路径或改返回结构。确需修改时，先评估兼容性并记入 `PROJECT_STATUS.md`。

## 数据库规范

- 表结构以 `app/models.py` 为准；任何结构变更必须新增 Alembic 迁移（`backend/alembic/versions/`）。
  已发布的迁移文件不可回改。当前最新为 `0015_alert_hits`（v2.12.0 发布基线；已在本机应用）。
- 严重度/风险等级统一用英文首字母大写：`Critical` / `High` / `Medium` / `Low`。
- 派生表（如 `incidents`）可以在根因修复后用维护端点按原始数据重算，但**绝不允许凭空造数据**。
- 维护端点参考：`POST /api/v1/admin/data-assets/backfill`、`POST /api/v1/admin/data-assets/rebuild-projection`
  （均带 `record_audit` 审计）。

## Docker / 部署方式

服务：`postgres`、`redis`、`backend`(8000)、`worker`、`beat`、`deployment-worker`、`frontend`(→`${HTTP_PORT}`)、`flower`。

```powershell
$src = (Resolve-Path ".\00-数据安全工具箱\source").Path
docker compose -p source -f "$src\docker-compose.yml" up -d --no-build --force-recreate backend worker beat deployment-worker frontend
```

**构建必须用 legacy builder**：本机 `docker compose build` 会因挂起的 `docker-buildx`/`docker-compose` 进程永久卡住。

```powershell
Get-Process -Name "docker-buildx","docker-compose" -ErrorAction SilentlyContinue | Stop-Process -Force
$env:DOCKER_BUILDKIT = "0"
docker build -f "$src\backend\Dockerfile" --target api               -t source-backend:latest "$src"
docker build -f "$src\backend\Dockerfile" --target analysis-worker   -t source-deployment-worker:latest "$src"
docker build -f "$src\frontend\Dockerfile" -t source-frontend:latest "$src\frontend"
```

单次镜像构建约 3–5 分钟（每次都会重装 pip 依赖）。查看进度：`docker ps -a` 中出现中间态 `pip install` 容器即为正常。

## 测试命令

```powershell
docker exec source-backend-1 sh -lc "cd /app && python -m pytest -q"        # 后端全量
docker exec source-backend-1 sh -lc "cd /app && python -m pytest tests/test_api.py -q"   # 单文件
docker exec source-frontend-1 sh -lc "cd /app && npx vitest run"            # 前端单测
docker exec source-frontend-1 sh -lc "cd /app && npx vue-tsc --noEmit"      # 前端类型检查
```

## 开发命令

```powershell
make up / down / logs / migrate / shell / test / lint / format     # 见 Makefile
```

## 禁止修改的内容

1. **不要在生产控制台导入测试数据**：`POST /api/v1/test/import` 会写入演示用文件/PCAP。
   交付与演示环境要求数据全部真实，禁止调用（`/test/status` 可用于自检）。
2. **不要在生产构建开启 mock**：`VITE_DEMO_MODE=true` 会让前端走 `src/mocks/adapter.ts` 假数据，
   仅限 `npm run dev:demo` / `build:demo`（5174）使用。
3. **不要扩大 `probe/uninstall.sh` 的删除白名单**：删除目标必须来自脚本内固定常量，
   不得读取命令行参数或目标机上的文件（以 root 读可变文件等于提权原语）；符号链接只删链接本身。
4. **不要改动探针与服务端的职责边界**：探针只做采集/上传/心跳/受控命令，
   不做风险评分、告警关联、报告生成。
5. **不要修改已发布的 Alembic 迁移**，也不要手改线上库结构。
6. 不要用 `git commit` 之外的方式改写历史；不要回滚用户未提交的修改。

## 重要约束

- 探针以只读、非侵入方式工作：旁路采集，不解密 TLS，不做串接阻断。
- 探针安装路径固定：代码 `/opt/data-security-toolbox`、配置 `/etc/data-security-toolbox`、
  运行数据 `/var/lib/data-security-toolbox`（`spool/` `rules/` `cache/`），systemd 单元 `data-security-toolbox-probe`。
- 管理账号 `admin`，密码取自仓库根目录 `.env` 的 `ADMIN_PASSWORD`。
- 本机 `apply_patch` 需要与文件行尾一致（仓库文件为 CRLF）；补丁分块尽量小。
- 不要在未确认的情况下操作真实探针主机（当前在线探针 `test123` 位于 `192.168.191.130`）。

## 数据资产修改入口

数据资产采集/展示优先读 `docs/数据资产开发入口.md`。采集协议在 `api/data_collection_schemas.py`，
采集路由在 `api/data_collection.py`，任务创建在 `services/probe_task_service.py`；
对象身份/覆盖/写入/投影/查询已拆入 `services/data_objects/`。旧 `data_object_service.py` 仅作兼容门面，
不要向其中新增实现。前端列表、采集状态与采集任务页分别在 `modules/data-security/composables/` 的
`useDataAssetList.ts`、`useDataAssetCollection.ts`、`useDataAssetJobs.ts`，页面只做组装；
边界由 `tests/test_data_asset_boundaries.py` 检查。

## 分析编排与任务入口

分析与事件关联编排在 `application/analysis.py`，不在 worker 里；任务行持久化在 `services/task_service.py`，
队列派发统一走 `services/task_dispatch.py`（按注册名，broker 不可用才回退本进程）。
worker 任务按职责分在 `workers/{analysis,notification,maintenance}_tasks.py`，注册名集中在
`workers/task_names.py`，生命周期在 `workers/task_runtime.py`；旧 `workers/tasks.py` 仅兼容门面，不要新增实现。
路由/服务不得导入 `app.workers.*`（端口模块除外）；Celery 任务名、参数顺序与队列路由属兼容边界。
边界由 `tests/test_task_boundaries.py` 检查。

## PCAP 域路由入口

PCAP 抓包域路由在 `api/pcaps.py`（上传、列表/详情/分析、包/流、协议/流量、DNS/HTTP/TLS、
提取清单/预览/下载、抓包告警共 18 条路径）；上传归属与队列背压在 `api/dependencies.py`
（`upload_probe_id`、`enforce_queue_backpressure`），Task 行序列化在 `api/task_presenter.py`。
子路由由 `app/api/v1.py` 的 `include_router` 只注册一次，`/api/v1` 前缀只叠加一次；
解析与提取仍在 `services/protocol_service.py`、`services/pcap_files.py`，路由只做鉴权、分页与响应结构。
边界由 `tests/test_pcap_boundaries.py` 检查（路径/方法冻结、全应用无重复注册）。

## 文件证据域路由入口

文件上传/列表/详情/下载/重新分析共 5 条路径在 `api/files.py`（含扩展名/MIME 过滤器与 `serialize_file`）；
上传归属复用 `api/dependencies.py::upload_probe_id`，Task 行序列化复用 `api/task_presenter.py::serialize_task`，
派发走 `services/task_dispatch.dispatch_task_row`。哈希与元数据仍在 `services/metadata_service.py`，检测仍在 worker；
路由只做鉴权、分页与响应结构。PCAP 内提取文件的预览/下载是另一套路径，仍在 `api/pcaps.py`，不要混在一起。
边界由 `tests/test_file_boundaries.py` 检查（路径/方法冻结、不复制共享守卫、全应用无重复注册）。

## 平台资产域路由入口

主机资产清单在 `api/assets.py`（`GET /assets`、`/assets/summary`、`/assets/relations`、`/assets/{asset_id}`），
资产行序列化导出为 `serialize_asset` 供其他读域复用；`/assets/{id}` 的检测、事件、IOC 行分别复用
`api/finding_presenter.py`、`api/incident_presenter.py`、`api/ioc_presenter.py`，时间归一化用
`core/datetimes.py::aware`，不要在路由里重写这三者。数据资产（`/data/assets`、`/data-types`、`/data-objects`）
是另一套边界，仍属 `api/data_assets.py` 与数据目录，不要混在一起。关联判定与评分仍在
`services/asset_service.py`、`incident_engine`。边界由 `tests/test_asset_boundaries.py` 检查。

## 事件与情报域路由入口

事件与情报路由在 `api/incidents.py`（`GET /incidents`、`GET|PATCH /incidents/{id}`、
`POST /incidents/correlate`、`POST /incidents/rebuild-attribution`、`GET /iocs`、
`GET /iocs/{id}/associations`）。关联计算必须走 `incident_engine`（`IncidentEngine.correlate`），
归属重建走 `incident_engine.attribution`，不要在路由里重写关联逻辑；行序列化用共享 presenter，
列表时间过滤用 `api/query_filters.py::string_time_filter`。边界由 `tests/test_incident_ioc_boundaries.py` 检查。

## 告警域路由入口

告警路由在 `api/alerts.py`（`GET /alerts`、`GET /alerts/summary`、`GET /alerts/stream`（SSE）、
`GET /alerts/{alert_id}`、`PATCH /alerts/{alert_id}`）。抑制状态、命中聚合与投递仍在
`services/alert_service.py`（`serialize_alert`、`list_alert_hits`、`publish_alert`、`event_type_for_status`），
不要在路由里重写。探针行序列化复用 `api/probe_presenter.py::serialize_probe`，规则解析复用
`api/rule_presenter.py::rule_definition`（`/rules` 路由同样引用它），不要在 v1 里另留副本。
边界由 `tests/test_alert_boundaries.py` 检查（路径/方法冻结、不复制共享守卫、全应用无重复注册）。

## 任务、审计与报表域路由入口

任务队列路由在 `api/tasks.py`（`GET|POST /tasks`、`GET /tasks/{task_id}`、
`POST /tasks/{task_id}/stop`、`DELETE /tasks/{task_id}`），行创建仍在 `services/task_service.py`、
过期仍在 `services/probe_task_service.py`（`expire_probe_tasks`、`visible_tasks`），Task 行序列化复用
`api/task_presenter.py::serialize_task`，不要在路由里重写停止/删除判定。
审计与报表路由在 `api/reports.py`（`POST /audit/logs`、`GET /audit/summary`、
`POST /reports/generate`、`GET /reports`、`GET /reports/{report_id}/download`），
汇总/日志分析仍在 `services/audit_service.py`，报告构建/渲染仍在 `services/report_service.py`；
报告行序列化 `serialize_report` 是本域私有实现（原 v1 `_serialize_report`），不要再复制回 v1。
边界由 `tests/test_tasks_reports_boundaries.py` 检查（路径/方法冻结、不复制共享守卫、全应用无重复注册）。

## 检测与引擎域路由入口

检测结果路由在 `api/detections.py`（`GET /detections`、`GET /detections/{detection_id}`、
`GET /analysis/results`）；行序列化复用 `api/finding_presenter.py::_serialize_detection`、
`api/incident_presenter.py::serialize_incident`、`api/pcaps.py::serialize_pcap`、
`services/alert_service.py::serialize_alert`，列表时间过滤用 `api/query_filters.py::string_time_filter`，
不要在路由里重写任一序列化或过滤。引擎目录路由在 `api/engines.py`（`GET /engine/registry`、
`POST /engine/pipeline`）：引擎清单必须读 `app.engine.registry`，规则清单必须走
`api/rule_presenter.py::rule_file_entries`，内部引擎名与 UI slug 的映射 `ENGINE_PRESENTATION`
随域移动，不要在 v1 或其他域再放一份。检测判定仍在 `app/engine/*`。
边界由 `tests/test_detection_engine_boundaries.py` 检查（路径/方法冻结、不复制共享守卫、全应用无重复注册）。

## Dashboard 与流量视图域路由入口

看板、风险总览、关系图与全局流量视图在 `api/dashboard.py`（`GET /risk/summary`、`GET /graph`、
`GET /dashboard/summary|risk-trend|severity|engines|incidents|high-risk-assets|sensitive-data|incident-trend`、
`GET /flows`、`GET /protocols`、`GET /network/live`）。所有数字都必须由 `app/models.py` 的行实时聚合，
不得落库缓存或写死；行序列化复用 `api/assets.py::serialize_asset`、`api/incident_presenter.py::serialize_incident`、
`api/pcaps.py::serialize_flow`、`api/probe_presenter.py::serialize_probe`，协议分层复用
`services/protocol_service.py::protocol_layer`，分页复用 `api/pagination.py`。
边界由 `tests/test_dashboard_boundaries.py` 检查（路径/方法冻结、不复制共享守卫、全应用无重复注册）。

## 探针域路由入口

探针注册/心跳/列表/删除/分析/扫描/指标与加密画像在 `api/probes.py`（`POST /probes/register`、
`POST /probes/{probe_id}/heartbeat`、`GET /probes`、`DELETE /probes/{probe_id}`、
`POST /probes/{probe_id}/analyze`、`GET /probes/{probe_id}/tasks`、`POST /probes/{probe_id}/scan`、
`GET /probes/{probe_id}/metrics`、`GET /crypto/probe-profile` 共 9 条路径）。探针鉴权走
`core/security.py` 与 `api/dependencies.py`，登记入册走 `deployment/enrollment.py`，
删除记录与远端卸载走 `services/probe_service.py`、`deployment/removal.py`，任务行仍由
`services/task_service.py` 创建；行序列化复用 `api/probe_presenter.py::serialize_probe` 与
`api/task_presenter.py::serialize_task`。队列派发统一走 `api/dependencies.py::dispatch_task`
（原 v1 `_dispatch`，v1 不再保留副本）。探针下发/回收、规则下发、扫描任务与采集上报分属
`api/deployments.py`、`api/rulesets.py`、`api/extensions.py`、`api/data_collection.py`，不要混在一起。
边界由 `tests/test_probe_boundaries.py` 检查（路径/方法冻结、不复制共享守卫、全应用无重复注册）。

## 集成与离线导入域路由入口

第三方适配器目录与 `/offline` 导入面在 `api/integrations.py`（11 条路径：`GET /integrations`、
`POST /integrations/{name}/analyze`、`POST /integrations/offline/upload|import`、
`GET /offline/resources`、`GET|POST /offline/cves`、`POST /offline/upload`、
`POST /offline/grype/update|import`、`GET /offline/grype/jobs/{identifier}`）。
适配器元数据与执行仍走 `app.integrations`（registry/runner）、离线包解析仍走
`app.integrations.offline_manager`、Grype 库仍在 `services/grype_library.py`、告警仍在
`services/alert_service.py`、事件聚合仍走 `incident_engine`，路由只做鉴权与响应结构。
`/offline/grype/*` 与 `POST /offline/cves` 原先在 `api/libraries.py`，本域收拢后 `libraries.py`
只保留 dlp 规则/规则源/规则导入；这四条保留了历史上的 `rule-libraries` tag，OpenAPI 不变。
worker 能力与规则清单的读取（`read_worker_capabilities`、`merge_capability`、`engine_rule_counts`）
下沉到 `api/runtime_status.py`，`/health` 与 `/integrations` 共用，不要在任一域里重写。
边界由 `tests/test_integration_offline_boundaries.py` 检查（路径/方法冻结、不复制共享守卫、全应用无重复注册）。

## 规则域路由入口

检测引擎规则面在 `api/rules.py`（5 条路径：`GET /rules`、`GET /rules/content`、`GET /rule-sources`、
`POST /rules/sync`、`POST /rules`）。规则枚举只有一份实现：`api/rule_presenter.py::rule_file_entries`
（内置规则与磁盘规则都在这里汇总，`/engine/registry` 也用它）；来源出处读 `app.rules.catalog`、
`app.rules.library`，在线拉取走 `app.rules.sync`，手工 Suricata/YARA 规则导入走
`app.integrations.offline_manager` 与 `yara` 编译器，写前校验不可绕过；
`POST /rules/sync` 的审计走 `services/audit_service.record_audit`。敏感数据（DLP）规则是另一类规则族，
仍在 `api/libraries.py`（`/dlp/rules*`），不要混在一起；规则集下发与版本仍在 `api/rulesets.py`。
边界由 `tests/test_rule_boundaries.py` 检查（路径/方法冻结、不复制共享守卫、全应用无重复注册）。

## v1 聚合边界（auth / health / 网络扫描 / 测试数据）

第十四批把 `api/v1.py` 里最后几个零散入口收进各自域，`v1.py` 自此只做子路由聚合
（`router_routes(v1.py)` 必须为空，由 `tests/test_auth_boundaries.py` 锁定）：

- 会话面在 `api/auth.py`（3 条路径：`POST /auth/login`、`POST /auth/logout`、`GET /auth/me`）；
  会话存储、Cookie 与口令校验仍走 `core/security.py` 与 `AdminSession`，`/auth/me` 的非生产快捷分支
  属于既有契约，不要改动。
- 平台健康在 `api/health.py`（`GET /health`）：Redis/Celery 队列深度走
  `services/task_dispatch.py::queue_depth`，worker 能力与规则清单走 `api/runtime_status.py`
  （与 `/integrations` 共用一份），探针行形状走 `api/probe_presenter.py`；
  `main.py` 对 `/api/v1/health` 的免鉴权放行是既有契约。
- 主动扫描在 `api/network_scan.py`（`POST /scan`、`GET /scan/{task_id}`）：端口选择走
  `services/scan_service.py`，探针侧排队走 `services/probe_task_service.py`，派发走
  `api/dependencies.dispatch_task`；扫描配置 `/scan-profiles*` 仍在 `api/profiles.py`。
- 手动测试数据在 `api/test_data.py`（`POST /test/import`、`POST /test/clear`、`GET /test/status`）：
  导入/清理/状态实现仍在 `services/test_service.py`，写入口的 opt-in 守卫
  `_require_test_data_import`（读 `settings.test_data_import_enabled`，默认关闭）随域下沉，
  两个写入口都必须先过这个守卫，不得绕过或复制。
- 边界由 `tests/test_{auth,health,network_scan,test_data}_boundaries.py` 检查
  （路径/方法冻结、不复制共享守卫、全应用无重复注册、v1 只聚合一次）。

## PCAP 工作台状态边界

工作台的状态与 API 编排在 `frontend/src/modules/network/pcap/composables/usePcapWorkbench.ts`，
`PcapWorkbench.vue` 只保留模板、弹窗与格式化（582 → 312 行）。
抓包列表/上传/分析轮询、包分页与详情、文件预览、TCP 流跟踪都在 composable 里：
`viewVersion`、`packetVersion`、`detailVersion`、`fileVersion`、`taskVersion` 的过期响应防护与
轮询 timer（卸载时清除）不要挪回组件，切换抓包后哪些请求作废由这五个版本号定义。
关闭预览弹窗的作废动作由 `closeFileDialog()` 承担——`let` 计数器不能靠返回值暴露给模板。
API 调用仍只走 `frontend/src/api`，不在组件里拼第二套 HTTP 客户端。
回归：`frontend/src/__tests__/pcap-workbench.test.ts`（组件行为）、
`pcap-workbench-state.test.ts`（状态、竞态与轮询）、`npm run typecheck`、`npm test`。

## 数据资产采集任务页状态边界

采集任务页（`modules/data-security/DataAssetJobs.vue`）的状态与 API 编排在
`frontend/src/modules/data-security/composables/useDataAssetJobs.ts`（159 行），页面只保留模板与按钮
（251 → 131 行）。任务列表按 `kind=data_asset_scan` 走 `api/tasks.ts::listTasks`——原来是页面自己调
`apiGet('/tasks', ...)`，两处是同一个请求；探针与扫描配置下拉、派发、取消、移除和 5 秒自动刷新都在
composable 里，轮询 timer 归 composable 所有并在卸载时清除，不要把 timer 挪回页面。
派发 payload 的既有语义：显式路径优先于扫描配置，路径非空且选了配置时两个字段都发；没有选中探针时
直接返回、不发请求。回归：`frontend/src/__tests__/data-asset-jobs-state.test.ts`（9 项）。

## 数据目录类型页状态边界

数据类型中心与类型详情（`DataTypeCenter.vue`、`DataTypeDetail.vue`）的状态分别在
`modules/data-security/composables/useDataTypeCenter.ts` 与 `useDataTypeDetail.ts`（页面 154 → 117、
134 → 99 行）。类型页顶部卡片必须直接用服务端去重后的 `totals` 与 `totals_scope`，不能把每行相加；
类型详情按路由 `category` 与分页查询，翻页走 `setPage()`——`page` 是 composable 返回的 ref，
模板里直接赋值只会改掉 setup 局部名字（同 PCAP 批的 `closeFileDialog`）。一次失败的刷新保留上一次
成功的数据，不把范围清空成假象。回归：`frontend/src/__tests__/data-type-catalog-state.test.ts`（7 项）。

## 数据目录对象与实例页状态边界

数据对象详情与实例详情（`DataObjectDetail.vue`、`AssetInstanceDetail.vue`）的状态分别在
`modules/data-security/composables/useDataObjectDetail.ts`（104 行）与
`useAssetInstanceDetail.ts`（72 行），页面只保留模板、行跳转与时间格式化（219 → 159、193 → 153 行）。
路由 id 以 `ComputedRef` 参数传入（composable 不自己 `useRoute`）；检测分页走 `setDetectionPage()`
——`detectionPage` 是 composable 返回的 ref，模板里直接赋值只会改掉 setup 局部名字
（同 PCAP 批的 `closeFileDialog`）。证据抽屉的加载/失败状态属于同一个 composable，不要在页面里
再写一份。回归：`frontend/src/__tests__/data-object-instance-state.test.ts`（8 项）。

## 扫描配置与规则版本页状态边界

扫描配置页与规则版本页（`ScanProfiles.vue`、`RuleVersions.vue`）的状态分别在
`modules/data-security/composables/useScanProfiles.ts`（188 行）与 `useRuleVersions.ts`（141 行），
页面只保留模板（289 → 155、256 → 156 行）；去掉缩进后，被移动的 132 行与 96 行脚本逐行未改。
扫描配置页的翻页走 `setPage()`——移动分页必须同时重新查询，写成一个方法能保证两件事一起发生。
草稿（`draft`、两个路径文本框）与「下发」弹窗都归 composable；规则版本页的
`probedVersion`/`probeField`/`shortHash` 是模板要用的纯函数，随 composable 一起导出。
回归：`frontend/src/__tests__/scan-profile-rule-version-state.test.ts`（17 项）。

## 文件分析、网络 DLP 与敏感发现页状态边界

文件分析、网络 DLP 与敏感发现（`FileAnalysis.vue`、`NetworkDlp.vue`、`SensitiveDiscovery.vue`）
的状态分别在 `modules/data-security/composables/useFileAnalysis.ts`（110 行）、
`useNetworkDlp.ts`（106 行）与 `useSensitiveDiscovery.ts`（63 行），页面只保留模板
（185 → 115、142 → 83、102 → 71 行）；去掉缩进后，被移动的 67 行、65 行与 36 行脚本逐行未改，
三个页面模板逐字节未改。文件分析的 4 秒抽屉刷新 timer 归 composable 并在卸载时清除；
网络 DLP 的 `evidenceRequest` 竞态守卫随 `openTransfer()` 一起进 composable，不要在页面里再写一份；
`FileRecord`/`FileDetail` 由 composable 导出（视图按类型导入），这是唯一的修饰改动。
回归：`frontend/src/__tests__/file-analysis-state.test.ts`（9 项）与
`frontend/src/__tests__/network-dlp-discovery-state.test.ts`（13 项）。

## 事件中心与告警中心页状态边界

事件中心与告警中心（`IncidentCenter.vue`、`AlertCenter.vue`）的状态分别在
`modules/operations/incidents/composables/useIncidentCenter.ts`（117 行）与
`modules/operations/alerts/composables/useAlertCenter.ts`（84 行），页面只保留模板
（268 → 193、215 → 164 行）；去掉缩进后，被移动的 75 行与 51 行脚本逐行未改，
两个页面模板逐字节未改。列表的筛选字段配置（`filterFields`）与攻击阶段标签（`stages`）
留在视图，属于静态展示；`activeStages`/`findings`/`confidence` 这类投影、全部 API 调用与
事件中心的手工关联整块进 composable。回归：
`frontend/src/__tests__/incident-alert-center-state.test.ts`（17 项）。

## 资产中心页状态边界

资产中心（`frontend/src/modules/asset/AssetCenter.vue`）的状态在
`modules/asset/composables/useAssetCenter.ts`（171 行），页面只保留模板（290 → 147 行）；
去掉缩进后，迁入的 145 行脚本逐行未改，模板逐字节未改。页面保留筛选字段配置
（`filterFields`）与 `formatDateTime`/`formatRiskScore` 这类静态展示；资产列表、详情抽屉、
关系图投影（`graphNodes`/`graphEdges`）与网络扫描控制台（平台/探针两种来源、3 秒轮询到终态、
`scanSummary` 汇总）整块进 composable。本批删除了页面里从未使用的 `useRouter()`（模板与脚本
都没有引用它），其余为机械搬迁；`loadProbes` 只在 composable 的 `onMounted` 里调用，视图不再
解构它。回归：`frontend/src/__tests__/asset-center-state.test.ts`（15 项）。

## 检测中心页状态边界

检测中心（`frontend/src/modules/operations/detections/DetectionCenter.vue`）的状态在
`modules/operations/detections/composables/useDetectionCenter.ts`（101 行），页面只保留模板
（183 → 111 行）；去掉缩进后，迁入的 78 行脚本逐行未改，模板逐字节未改。页面保留筛选字段配置
（`filterFields`，引擎下拉的选项来自 composable 暴露的 `engineOptions`）与 `formatDateTime`；
发现列表、详情抽屉与手动流水线（解析 JSON、拆日志行、`ElMessage` 提示）整块进 composable。
引擎下拉仍按 `detection_engine || name` 取值、标签取 `label || name` 并附发现数，注册表请求失败时
选项保持为空且不影响发现列表。回归：
`frontend/src/__tests__/detection-center-state.test.ts`（10 项）。

## 与其他文档的关系

- 交付/演示口径：`docs/领导演示方案.md`
- 部署与运行：`docs/部署与运行手册.md`、`docs/deployment.md`、`docs/offline-deployment.md`
- 验收：`docs/acceptance_test.md`、`docs/acceptance_test_report.md`
- 版本策略：`docs/versioning.md`、`CHANGELOG.md`
