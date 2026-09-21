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
  目标数据库直连盘点在 `database_connections.py`（`/database-connections*`）。
- 列表统一用 `page` / `page_size`，返回 `{items, total, page, page_size}`（见 `app/api/pagination.py`）。
- 认证：控制台用会话 Cookie / Bearer；探针接口用 `X-Probe-ID` + `X-Probe-Token`。
- 不要随意删除已有 API、改路径或改返回结构。确需修改时，先评估兼容性并记入 `PROJECT_STATUS.md`。

## 数据库规范

- 表结构以 `app/models.py` 为准；任何结构变更必须新增 Alembic 迁移（`backend/alembic/versions/`）。
  已发布的迁移文件不可回改。当前最新为 `0016_database_connections`（新增 `database_connections` 表，
  并给 `asset_instances` / `detections` 增加来源列、把实例唯一键从 `(probe_id, path)` 改为 `(owner_key, path)`；
  已随 API 容器启动时的 `alembic upgrade head` 应用）。
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

## 引擎详情页状态边界

引擎详情（`frontend/src/modules/engines/EngineDetail.vue`）的状态在
`modules/engines/composables/useEngineDetail.ts`（114 行），页面只保留模板（208 → 126 行）；
去掉缩进后，迁入的 83 行脚本逐行未改，模板与样式逐字节未改。composable 接收路由派生的
`name`（`ComputedRef<string>`），路由、导航与 `executionLabels` 这类静态标签留在视图。
控制台路由名（`/engines/sigma`）与发现里存的名字（`sigma_log_engine`）不同，仍由注册表解析；
规则数仍先取注册表、再取同名适配器，`/health` 只用于运行态展示。回归：
`frontend/src/__tests__/engine-detail-state.test.ts`（11 项）。

## 看板页状态边界

看板（`frontend/src/modules/dashboard/Dashboard.vue`）的状态在
`modules/dashboard/composables/useDashboard.ts`（94 行），页面只保留模板（195 → 127 行）；
去掉缩进后，迁入的 69 行脚本逐行未改，模板与样式逐字节未改。页面保留路由与 `formatDateTime`/
`formatRiskScore` 这类静态展示（模板里的 `Incident`/`Asset` 类型注解也留在视图），汇总卡、
风险仪表、运行态、两条趋势与四个图表序列整块进 composable。两处环形图仍走同一套四级刻度
（`levelBreakdown`：先按 `severityOrder` 排序、再用 `severityTagColors` 上色、值为 0 的档位丢弃），
接口多出来的档位（例如敏感类别的 `Unknown`）仍排在刻度之后。回归：
`frontend/src/__tests__/dashboard-state.test.ts`（7 项）。

## 安全审计页状态边界

安全审计（`frontend/src/modules/operations/audit/SecurityAudit.vue`）的状态在
`modules/operations/audit/composables/useSecurityAudit.ts`（69 行），页面只保留模板
（167 → 121 行）；去掉缩进后，迁入的 50 行脚本逐行未改，模板与样式逐字节未改。页面保留
`riskLabels` 这类静态标签与 `formatRiskScore`；审计汇总、日志分析输入与结果、以及模板直接调用的
`matchGroups`（把服务端 `log_summary.matches` 投影成固定顺序的分组）整块进 composable。
汇总页只读；日志分析失败进 `logError`（页面级 `error` 不受影响），空内容不发请求。回归：
`frontend/src/__tests__/security-audit-state.test.ts`（7 项）。

## 流量视图页状态边界

流量视图（`frontend/src/modules/network/traffic/LiveTraffic.vue`）的状态在
`modules/network/traffic/composables/useLiveTraffic.ts`（77 行），页面只保留模板（143 → 90 行）；
去掉缩进后，迁入的 53 行脚本逐行未改，模板与样式逐字节未改。页面保留路由与
`formatDateTime`/`formatBytes`。实时告警流是一个 `EventSource`，归 composable 所有：挂载时打开、
卸载时关闭（`onBeforeUnmount`），只保留最新 50 条；非法事件静默丢弃。抓包速率仍从最近一次已分析
捕获推导（没有专门的实时接口），无实时窗口时三项为 `null`。注：`recentPcaps` 仍在加载但模板未渲染，
本批保持原样。回归：`frontend/src/__tests__/live-traffic-state.test.ts`（8 项）。

## 算法评估页状态边界

算法评估（`frontend/src/modules/tools/AlgorithmEvaluation.vue`）的状态在
`modules/tools/composables/useAlgorithmEvaluation.ts`（141 行），页面只保留模板（306 → 196 行）；
去掉缩进后，迁入的 116 行脚本逐行未改，模板与样式逐字节未改（175 行）。页面保留三个展示组件与
静态语言下拉 `languages`。密码评估在浏览器本地完成，只读探针列表与单个探针的密码画像；复杂度
分析用 `acorn` AST 完全本地计算。`cryptoLevelTone`（等级 → 颜色）随结果进 composable；从探针自动
识别在画像字段为空时回退默认配置，并把 `passwordSignals` 按「密码/认证」维度并入评估发现。
回归：`frontend/src/__tests__/algorithm-evaluation-state.test.ts`（15 项）。

## 威胁情报与规则页状态边界

威胁情报与规则三页的状态都在 `modules/threat/composables/`：规则中心（`RulesCenter.vue` 110 → 65 行，
`useRulesCenter.ts` 74 行，迁入 52 行）、CVE 中心（`CveCenter.vue` 126 → 60 行，`useCveCenter.ts` 92 行，
迁入 70 行）与 IOC 中心（`IocCenter.vue` 118 → 82 行，`useIocCenter.ts` 59 行，迁入 39 行）；去掉缩进后，
迁入脚本逐行未改，三页的模板与样式逐字节未改。页面只保留静态展示：执行状态标签、CVSS 等级映射、
筛选字段配置与时间格式化函数。规则库仍以 `include_content: false` 读取、内容按需展开拉取；CVE 页的
Grype 导入任务轮询（2s）由 composable 持有，任务 id 存 `localStorage`，卸载时清除定时器；IOC 开关按
`metadata.enabled` 取反提交后重载。回归：`frontend/src/__tests__/threat-center-state.test.ts`（32 项）。

## 目标数据库直连盘点边界（2026-09-20）

平台自己连接目标数据库（不经过探针、不经过 SSH 隧道），由状态与 API 编排在
`backend/app/services/database_scan/`（`adapters` 连接与反射、`detect` 按列复用共享敏感引擎、
`ingest` 落库、`connection_service` 校验与凭据、`scan` 编排），路由在 `api/database_connections.py`，
任务名 `security_toolbox.database_scan`（`analysis_tasks.database_scan_task`）。
前端 `DatabaseConnections.vue` + `composables/useDatabaseConnections.ts` + `api/databaseConnections.ts`。

这些约束不要放宽：

- **只读**：`adapters` 在连接池 connect 钩子里对每条连接执行 `SET SESSION TRANSACTION READ ONLY`
  并回读 `@@session.transaction_read_only`；服务器回答「可写」时必须拒绝采集。不要为「方便」去掉校验。
- **不给 SQL 文本入口**：标识符一律来自反射；任何新增接口都不得接受用户提交的 SQL 片段。
- **口令只写不读**：库内存密文，响应与审计只允许出现 `password_set`；解密失败按凭据错误处理，不得回退到别的口令。
- **检测口径**：只有值命中计入 counts/categories，字段名/关键字线索进 `candidates`，不要把列名当数据。
- **退役**：未再见到的表只在范围完整（`complete_scope`）时才标记退役，取消/超时不得退役。

路径/哈希：`asset_instances.owner_key` 为 `probe:<id>` 或 `db:<连接 id>`，与 `source_kind` 一起构成来源；
证据原文出口仍只有 `GET /api/v1/detections/{id}/evidence`。回归：`backend/tests/test_database_*.py`
（真机门控 `test_database_scan_target.py` 需要 `.local/db-target.env`）与
`frontend/src/__tests__/database-connections-state.test.ts`。
## 共享文件来源边界（2026-09-20）

平台自己连接 FTP / 显式 FTPS / SFTP 共享目录（不经探针、不经 SSH 隧道），由状态与 API 编排在
`backend/app/services/file_scan/`（`adapters` 只读传输、`credentials` 口令加密、`service` 配置与任务快照、
`scan` 预算化枚举与临时文件清理、`ingest` 复用共享敏感引擎与证据/资产写入口），路由在
`api/file_sources.py`，任务名 `security_toolbox.file_source_scan` 与 `security_toolbox.file_source_schedule`
（beat 每 60 秒检查到期来源）。前端 `SourceManagement.vue`（来源管理，「共享文件」页签内嵌 `FileSources.vue`）
`+ composables/useFileSources.ts + api/fileSources.ts`；迁移 `0017_file_sources`。

这些约束不要放宽：

- **只读**：适配层只用 `MLSD`/`LIST`、`RETR` 与 SFTP 读操作，不提供写入/删除/改名入口；远端名字先经
  `child_path` 校验（`..`、路径分隔符、CR/LF/NUL 一律拒绝），符号链接只记 `skip`、永不跟随。
- **列目录兼容**：优先 `MLSD`，服务器回答 500/502（如 vsFTPd 3.0.5）时回退解析 `LIST`；550 等真实回答
  不得重试为其他命令，必须归类上报。
- **错误只报类别**：`auth_error`/`path_error`/`protocol_error`/`timeout`/`dns_error`/`unreachable`；
  服务器回显文本可能带账号口令，任何情况下不得写进任务、来源记录或日志。
- **口令只写不读**：库内存密文（AAD 绑定来源 id 与用户名），响应与审计只允许出现 `password_set`；
  改名/换密钥后按凭据错误处理，不得回退到别的口令。改用户名必须同时提供新口令。
- **目标身份不可变**：协议、地址、端口创建后不可改（要换端点就新建来源，保留原来源历史）；**共享目录可改**：
  路径按远端绝对路径存储，移动目录只让旧路径在下一次完整采集后标记 `NOT_OBSERVED`，不删除资产。
  同一来源同时只允许一个采集任务；采集中的来源不可删除，删除只移除配置，已采集资产与证据保留。
- **诚实覆盖度**：逐文件记录 `coverage` 与 `termination_reason`；只有范围完整时才把未再观测到的路径标记
  `NOT_OBSERVED`，取消/超时/预算截断都不退役。

路径/哈希：`asset_instances.owner_key` 为 `probe:<id>`、`db:<连接 id>` 或 `file-source:<来源 id>`，与
`source_kind`（`file`/`database`/`file_share`）一起构成来源；实例详情接口必须返回
`source_kind`/`owner_key`/`source_name`，页面按三类显示，不得把共享文件或数据库来源显示成探针。
证据原文出口仍只有 `GET /api/v1/detections/{id}/evidence`。回归：`backend/tests/test_file_sources.py` 与
`frontend/src/__tests__/file-sources-state.test.ts`、`asset-inventory-state.test.ts`。


## 统一规则源与命中原文边界（2026-09-20）

控制台手写的规则、probe 内置包、文件扫描、数据库扫描与网络防泄密跑的是**同一个敏感引擎**：
平台侧唯一入口是 `backend/app/services/sensitive_engine.py`（`scan_engine()` = 内置包 + 规则库手写规则，
按 `analyst_signature()`（`data/integrations/dlp_rules/*.json` 的 mtime+size）缓存重建；对外还有
`scan_all()` / `analyst_rules()` / `has_analyst_rule()` / `scan_timeouts()` /
`to_legacy_hits(..., include_matches=True)`）。消费方 `engine/data_engine/engine.py`、
`services/file_scan/ingest.py`、`services/database_scan/detect.py`、`services/dlp_service.py` 一律走它，
**不要再各写一份规则加载**。"一条规则、三处命中、带原文"就是这条线的验收口径。

这些约束不要放宽：

- **一条规则一处定义，两处生效面**：规则只写规则库（`manual` / `presidio_static`）；
  `ruleset_service.sync_analyst_rules()` 把它镜像进规则集的**工作副本**（已发布版本不可变），
  **要下发给探针必须人工发布**。控制台加规则对平台侧三条链路立即生效，探针侧要等发布。
- **手写规则不受类别白名单约束**：网络防泄密的 `policy['categories']` 只过滤内置包命中；操作者自己写的规则
  命中一律上报（作者意图优先），不要用策略勾选项把它滤掉。
- **实体大小写保留**：`to_legacy_hits` 只对内置包回落历史小写名，自定义实体（`COMPANY`、`测试`）原样输出；
  类别过滤按大小写不敏感比较。
- **原文只走 `matches`**：每条命中 ≤3 条、`value` ≤120、`context` ≤240 字符（探针与平台两侧各自重裁，
  平台侧只接受非空 `value`）；`shared/sensitive_detection/report_guard.py` 把它列为 `RAW_TEXT_KEYS`。
  计数、类别、规则元数据、`samples` 永远不含值，只命中字段名/关键字的命中 `matches` 为空列表。
- **策略关键词与文件指纹**：关键词命中标 `rule_source='policy_keyword'`（原文由
  `shared/sensitive_detection/engine.py::text_matches()` 生成），文件指纹命中标 `rule_source='policy_fingerprint'`
  且 `matches=[]`；`analyze_capture()` 不得再往策略字典里写 `managed_rules`（每次调用必须用局部
  `rule_timeouts`，否则会跨任务累积）。
- **告警阈值不是命中阈值**：命中是否进告警中心还取决于风险分与 `alert_policy`
  （`high_finding_min_risk` 默认 60）。同一份命中，目的地址是内网（`exposure_factor=2.0`）时
  `risk=51` 不告警、是公网（`exposure_basis=external_destination`）时 `risk=76.5` 才告警——
  这是设计边界，改动它要用户确认，不要顺手调。

回归：`backend/tests/test_dlp_detection_quality.py`、`test_rule_libraries.py`、
`tests/shared/test_engine_wiring.py` 与 `frontend/src/__tests__/network-dlp-discovery-state.test.ts`。


## 与其他文档的关系

- 交付/演示口径：`docs/领导演示方案.md`
- 部署与运行：`docs/部署与运行手册.md`、`docs/deployment.md`、`docs/offline-deployment.md`
- 验收：`docs/acceptance_test.md`、`docs/acceptance_test_report.md`
- 版本策略：`docs/versioning.md`、`CHANGELOG.md`


## 数据库连接页状态边界（2026-09-21 第三十一批）

`frontend/src/modules/data-security/composables/useDatabaseConnections.ts` 是协调入口：负责列表、选中连接、
删除/测试与刷新；编辑草稿/保存进 `useDatabaseConnectionForm`，库表范围/派发进 `useDatabaseScope`，
详情/历史/抽屉与 5 秒轮询进 `useDatabaseScans`。子模块只通过显式响应式参数与回调协作，不反向导入入口。
`DatabaseConnectionForm.vue` / `DatabaseScanDetail.vue` 是展示组件，不调用 API；表单使用父级草稿，
密码只写不读、编辑空密码不提交、保存成功才清空。timer 只有 scans 一处持有，初次加载后启动、卸载清除。
纯标签在 `databaseConnectionPresentation.ts`，旧入口保留返回字段与 `ConnectionForm` 类型导出。
回归：`database-connections-state.test.ts`、`database-connections-page.test.ts`、typecheck 与全量 vitest。
