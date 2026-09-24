# AGENTS.md

本文件只保存长期稳定的信息（项目是什么、怎么开发、有哪些硬约束）。
临时任务进度看 `TASK.md`，项目整体状态看 `PROJECT_STATUS.md`，架构看 `docs/architecture.md`。

新会话开始工作前：先读这四个文件 → 再看 `git status` / `git log --oneline -10` → 最后核对真实代码。
**不要只依赖聊天历史判断项目状态。**

## 项目名称

数据安全监测检测工具箱（原名 Data Security Toolbox）。git 仓库根目录就是本目录
（`0901-工具箱开发/`），本文档及 `TASK.md` / `PROJECT_STATUS.md` 中的相对路径均相对仓库根目录。

## 项目用途

面向企业内网的数据安全检查与合规检测工具箱：在被检查主机上部署轻量探针采集流量与文件，服务端用多引擎分析，
产出资产、敏感数据资产、检测发现（Finding）、关联事件（Incident）、告警与检查报告，服务于数据安全合规检查服务交付。

## 技术栈

| 层 | 技术 |
| --- | --- |
| 后端 | Python 3.11（`python:3.11-slim`）/ FastAPI / SQLAlchemy 2.0 / Alembic / Celery / Redis 7.4 / PostgreSQL 16.6 |
| 前端 | Vue 3.5 + TypeScript 5.7 + Vite 6 + Element Plus 2.9 + ECharts 5.6 + Pinia 2.3 + vue-router 4.5 + Vue Flow 1.48；构建用 `node:24-bookworm`，运行 `nginx:1.27-alpine` |
| 探针 | 单进程 Python（`probe/probe.py`）+ systemd 单元；依赖 tshark/dumpcap 采集 |
| 部署 | Docker Compose（`docker-compose.yml` 本地 / `docker-compose.prod.yml` 生产 / `docker-compose.integrations.yml` 集成 / `docker-compose.dev.yml` 开发） |
| 测试 | 后端 pytest；前端 vitest + `vue-tsc --noEmit` |

## 目录结构

```
<仓库根>/
├── backend/                 # FastAPI + Celery 后端
│   ├── app/
│   │   ├── api/             # HTTP 路由，43 个模块按域拆分（v1.py 只做聚合）
│   │   ├── application/     # 分析编排（analysis.py）
│   │   ├── core/            # 配置、数据库、日志、时间归一化等基础设施
│   │   ├── deployment/      # 探针下发/回收的状态机与记录
│   │   ├── domain/          # 跨域领域原语（evidence_identity.py）
│   │   ├── engine/          # 检测引擎层（core + 各引擎，见下）
│   │   ├── incident_engine/ # 事件关联（Finding -> Incident）
│   │   ├── integrations/    # 第三方适配器（Zeek/Suricata/MISP/离线导入等）
│   │   ├── rules/           # 规则目录、规则库、解释器与同步
│   │   ├── services/        # 领域服务（53 个模块 + data_objects 等子包）
│   │   ├── templates/reports/
│   │   ├── threat_intel/    # 威胁情报引擎（IOC 匹配、CVE 关联）
│   │   ├── workers/         # Celery 任务（按职责拆分）+ 注册名
│   │   └── main.py / models.py / schemas.py
│   ├── alembic/versions/    # 数据库迁移
│   └── tests/               # pytest 用例
├── frontend/                # Vue 控制台（nginx 静态托管 + /api 反代）
│   └── src/{api,composables,components,modules,router,stores,types,utils,views,mocks,styles,assets}
├── probe/                   # 探针源码、install.sh / uninstall.sh、systemd 单元
├── shared/                  # 前后端/探针共享逻辑（scanning、sensitive_detection）
├── scripts/                 # seed.py、离线打包、探针分发包构建、E2E 脚本
├── deploy/                  # deploy.sh / undeploy.sh / deploy.conf（离线部署入口）
├── tools/e2e/               # 端到端脚本
├── docs/                    # 设计、部署、验收、演示文档
├── data_security_toolbox_manual_testpack/   # 手工测试样本（compose 以只读挂载）
├── data/                    # 运行期数据（挂载点，通常为空）
├── deploy-data/             # 本地 compose 栈的持久化根（gitignore，勿删，见“存储与容量保护”）
└── docker-compose*.yml      # 本地 / 生产 / 集成 / 开发四套编排
```

## 核心模块说明

- `app/engine/`：统一检测引擎层。所有检测器实现 `DetectionEngine.analyze(context) -> list[DetectionResult]`，
  由 `EngineRegistry` 注册、`DetectionPipeline` 调度（在 `engine/core/`）。现有：`asset_engine`、`compliance_engine`、
  `data_engine`、`protocol_engine`、`risk_engine`、`traffic_engine`，以及独立实现的 `dlp_engine.py`、`log_engine.py`。
- `app/application/analysis.py`：分析编排（谁在什么时机跑哪些引擎、如何合并 Finding、何时做事件关联与告警），
  **不在 worker 里**。`app/workers/{analysis,notification,maintenance,deployment}_tasks.py` 只保留任务本体。
- `app/services/task_dispatch.py`：队列派发的唯一出口（按注册名，broker 不可用才回退本进程）；
  任务行持久化在 `app/services/task_service.py`。
- `app/domain/evidence_identity.py`：从 Finding 的 `evidence` 解析**平台资产身份**（主机/指标），
  与 `services/data_objects/identity.py` 的**数据对象身份**（两个文件是否同一份）刻意分开；
  资产、告警、事件与去重都消费这一份，不要把地址解析写第二遍。
- `app/incident_engine/engine.py`：把多个 Finding 按时间窗口 + 资产 + IOC 聚合成 Incident；
  对外暴露 `evidence_asset_keys(evidence)` / `evidence_ioc_keys(evidence)` 供其他模块复用同一套身份解析。
- `app/services/protocol_service.py`：PCAP/协议解析与分类（`protocol_layer` 区分链路/网络/传输/应用层）。
- `app/deployment/`：探针下发与回收（SSH 下发、状态机、事件流水、生产文件清理清单）。
- `app/services/storage_guard.py`：平台自有数据分区的容量保护（见“存储与容量保护”）。
- `shared/`：前后端/探针共用的扫描与敏感数据逻辑；`shared/scanning/ocr.py` 与
  `shared/scanning/document_types.py` 负责 OCR 与红头/涉密件判定。
- `frontend/src/modules/`：控制台按业务域分包 —— `dashboard`、`tasks`、`data-security`、`network`、`collection`。

## 编码规范

- Python：ruff（`line-length = 100`，`select = ["E","F","I","B","UP"]`，`target-version = "py311"`，
  配置在 `backend/pyproject.toml`）。E501 历史存量很多，只对新增/修改的代码负责，不要批量重排老文件。
- 注释写“为什么”，不写“做了什么”；修 bug 时在关键处注明根因，避免后人再踩。
- 前端没有 eslint/prettier 配置，质量靠 `npm run typecheck` + `npm test` 把关。
- 改动保持最小化：不要为了小功能大规模重构无关代码，不要顺手改文件名或变量名。

## API 规范

- 统一前缀 `/api/v1`；后端容器监听 8000，控制台由 nginx 监听容器内 80、宿主 `${HTTP_PORT}`（`.env` 默认 8080）。
- 路由按域拆到 `app/api/` 下的独立模块（共 43 个）。`app/api/v1.py` **只做聚合**：它挂载 21 个子路由，
  自身 `router_routes(v1.py)` 必须为空（由 `backend/tests/test_test_data_boundaries.py` 锁定）。
  另有 6 个路由器**不经 v1**、由 `app/main.py` 直接挂载：`deployments`(前缀 `/api/v1/probe-deployments`)、
  `extensions`、`libraries`、`profiles`、`data_catalog`、`rulesets`（后五者自带 `/api/v1` 前缀）。
  新增域：先决定挂 v1 还是 main.py，不要两边都挂。
- 跨域复用的鉴权与上传守卫放 `api/dependencies.py`；跨域复用的响应结构放 `api/*_presenter.py`
  （`finding_presenter` / `incident_presenter` / `ioc_presenter` / `probe_presenter` / `task_presenter` / `rule_presenter`）。
- 列表统一用 `page` / `page_size`，返回 `{items, total, page, page_size}`（见 `app/api/pagination.py`）。
- 列表排序统一用 `order_by`：`field` 升序、`-field` 降序，白名单在 `app/api/list_sort.py`，
  **未知列直接 400**（`{"error":"unsupported_sort","allowed":[...]}`），不要静默忽略。
- 列表时间过滤统一用 `app/api/query_filters.py`，不要在路由里另写一套比较。
- 认证：控制台用会话 Cookie / Bearer（`core/security.py`）；探针接口用 `X-Probe-ID` + `X-Probe-Token`。
- 不要随意删除已有 API、改路径或改返回结构。确需修改时，先评估兼容性并记入 `PROJECT_STATUS.md`。

## 数据库规范

- 表结构以 `app/models.py` 为准；任何结构变更必须新增 Alembic 迁移（`backend/alembic/versions/`）。
  已发布的迁移文件不可回改。当前最新为 `0019_policy_group_fingerprints`（随 API 容器启动时的
  `alembic upgrade head` 应用）。
- 严重度/风险等级统一用英文首字母大写：`Critical` / `High` / `Medium` / `Low`。
- 派生表（如 `incidents`）可以在根因修复后用维护端点按原始数据重算，但**绝不允许凭空造数据**。
- 维护端点参考：`POST /api/v1/admin/data-assets/backfill`、`POST /api/v1/admin/data-assets/rebuild-projection`、
  `POST /api/v1/admin/findings/purge-false-positives`（均带 `record_audit` 审计）。

## 存储与容量保护

平台自己的数据分区是唯一能把自己写满的生产者（探针持续上传段，先于分析完成）。
两个独立限制都由 `app/services/storage_guard.py` 强制，且都按 `STORAGE_DIR` 真实所在的分区测量：

- **硬上限** `PCAP_STORAGE_MAX_GB`（`.env` 默认 100）：超限时**淘汰最旧的段文件**；
- **可用空间下限** `PCAP_STORAGE_MIN_FREE_GB`（默认 5）/ `PCAP_STORAGE_MIN_FREE_PERCENT`（默认 10）：
  低于下限**先拒绝新上传**（HTTP 429/507，带 `Retry-After`），而不是等盘满再崩。

淘汰只删文件、不删数据库行，所以分析结果、Finding、告警仍可归属于它来自的段。
短周期 beat 任务 `security_toolbox.enforce_pcap_storage_cap` 负责在还有余量时提前执行。
线上排查空间问题先看这里和 `GET /api/v1/health`，不要在业务代码里再加一套删除逻辑。

## Docker / 部署方式

服务：`postgres`、`redis`、`backend`(8000)、`worker`、`pcap-worker`、`beat`、`deployment-worker`、
`frontend`(→`${HTTP_PORT}`)、`flower`。持久化统一落在 bind mount `${DATA_ROOT:-./deploy-data}`
（`deploy-data/postgres`、`deploy-data/redis`、`deploy-data/backend`），**不是命名卷**。

```powershell
docker compose -p source -f ".\docker-compose.yml" up -d --no-build --force-recreate backend worker beat deployment-worker frontend
```

**构建必须用 legacy builder**：本机 `docker compose build` 会因挂起的 `docker-buildx`/`docker-compose` 进程永久卡住。

```powershell
Get-Process -Name "docker-buildx","docker-compose" -ErrorAction SilentlyContinue | Stop-Process -Force
$env:DOCKER_BUILDKIT = "0"
docker build -f backend\Dockerfile --target api             -t source-backend:latest .
docker build -f backend\Dockerfile --target analysis-worker -t source-worker:latest .
docker build -f frontend\Dockerfile -t source-frontend:latest frontend
```

单次镜像构建约 3–5 分钟（每次都会重装 pip 依赖）。查看进度：`docker ps -a` 中出现中间态 `pip install` 容器即为正常。

## 测试命令

```bash
docker exec source-backend-1 sh -lc "cd /app && python -m pytest -q"                     # 后端全量
docker exec source-backend-1 sh -lc "cd /app && python -m pytest tests/test_api.py -q"   # 单文件
docker exec source-frontend-1 sh -lc "cd /app && npx vitest run"                          # 前端单测
docker exec source-frontend-1 sh -lc "cd /app && npx vue-tsc --noEmit"                    # 前端类型检查
```

- 后端测试需要 `SECRET_KEY`（或 `DATABASE_CREDENTIAL_KEY`）；本机跑容器内全量前先从 `.env` 取值导出，
  否则会多出成批 `CredentialError` 假失败。
- 已知历史失败（与本次改动无关，不要在无关任务里顺手修）：`tests/test_rule_libraries.py` 收集报错、
  `probe_packages/probe-3.7.0/amd64` 缺失导致的 3 项、`test_distribution.py::test_backend_images_build_from_the_repository_root`
  （断言 4 个 Dockerfile、实际 2 个），以及需要完整栈的 `test_api.py::test_health`、
  `test_gap_fixes.py` 的 worker/zeek/suricata 项。

## 开发命令

```bash
make up / down / logs / migrate / shell / test / lint / format / build / frontend-build   # 见 Makefile
```

## 前端路由与页面

`frontend/src/router/index.ts` 只有 8 条真实路由（其余是深链重定向，见同文件）：

| 路由 | 组件 | 说明 |
| --- | --- | --- |
| `/login` | `views/LoginView.vue` | 登录（`meta.public`，不自动刷新） |
| `/` | `modules/dashboard/DashboardScreen.vue` | 数据安全态势大屏，`meta.layout='screen'`，无侧边栏/顶栏，固定深色 1920×1080 |
| `/cockpit` | `modules/dashboard/cockpit/DashboardCockpit.vue` | 数据安全驾驶舱，控制台壳层内的日常首页 |
| `/tasks` | `modules/tasks/TaskCenter.vue` | 任务中心（派发 + 进度 + 来源 + 扫描配置） |
| `/data-assets` | `modules/data-security/DataAssetHub.vue` | 数据资产 hub（对象模型 / 清单 / 评估 / 网络资产 / 密码评估 分 tab） |
| `/collection-rules` | `modules/collection/CollectionRules.vue` | 采集与规则（来源、扫描配置、采集任务、规则集、版本、策略分组、指纹、出境名单、漏洞库） |
| `/files` | `modules/data-security/FileEvidence.vue` | 文件证据（风险文件 / 风险 PCAP） |
| `/network/dlp` | `modules/data-security/flow/DataFlowProtection.vue` | 数据流动与防护（风险流动报告 / 出境报告） |

侧边栏分组在 `router/menu.ts`（`menuGroups`）；同一路由的多份菜单项靠 `view` query 区分高亮与深链，
所以**同一个 route 可以出现多次**，这不是重复。`/screen` 只是重定向到 `/`，不要再把大屏挂回去。
控制台**默认浅色**（`main.ts` 只在 `dst-theme === 'dark'` 时深色），主题状态在 `utils/theme.ts`；
ECharts 的 option 在构建时就把颜色写死，`components/charts/{Bar,Donut,Gauge,Trend}Chart.vue` 必须继续监听
`themeMode` 重建 option，否则切到浅色后画布会留着深色网格与轴色。壁挂大屏不受主题影响（固定深色）。

## 前端状态与共享 composable 边界

- 视图只留版式、路由与格式化；状态与 API 编排放同目录 `composables/`。翻页这类需要“同时改状态并重新查询”的动作
  必须写成 composable 的方法（如 `setPage()`）——composable 返回的 `page` 是 ref，模板里直接赋值只会改掉
  setup 局部名字。
- 轮询 timer 归 composable 所有，并在卸载时清除；不要把 timer 挪回页面。
- **自动刷新只有一个实现**：`frontend/src/composables/useAutoRefresh.ts`。它统一保证三件事——
  上一拍没回来就不再排下一拍（慢接口不会瞬间变成 N 个并发请求）、标签页隐藏时完全不轮询、
  组件卸载即清 timer。刷新一律走 `load({ silent: true })`：**后台失败保留上一次成功的数据**，不清空成假象。
  间隔按数据变化速度取值（任务中心 15 s、大屏/驾驶舱 30–60 s、规则库/漏洞库 120 s）。
  新增页面刷新必须复用它，不要再各写一份 `setInterval`。
- **列表筛选排序**：后端 `order_by` 走 `app/api/list_sort.py` 白名单；前端把 Element Plus 的 `@sort-change`
  归一成 `order_by` 拼写（`frontend/src/composables/useTableSort.ts`）并**同时把页码复位到第 1 页**
  ——只换顺序不换页码，看到的是“新顺序下早已不存在的那一页”。一次取全的列表在浏览器内筛选排序，
  不为此多打一次请求。当前已接入：`/tasks`、`/files`、`/pcaps`、`/data/assets`、`/network/assets`、
  `/asset-instances`、`/offline/cves`。

## 分析编排与任务入口

分析与事件关联编排在 `application/analysis.py`，不在 worker 里；任务行持久化在 `services/task_service.py`，
队列派发统一走 `services/task_dispatch.py`（按注册名，broker 不可用才回退本进程）。
worker 任务按职责分在 `workers/{analysis,notification,maintenance,deployment}_tasks.py`，注册名集中在
`workers/task_names.py`，生命周期在 `workers/task_runtime.py`；旧 `workers/tasks.py` 仅兼容门面，不要新增实现。
路由/服务不得导入 `app.workers.*`（端口模块除外）；Celery 任务名、参数顺序与队列路由属兼容边界。
边界由 `tests/test_task_boundaries.py` 检查。

## 数据资产修改入口

数据资产采集/展示优先读 `docs/数据资产开发入口.md`。采集协议在 `api/data_collection_schemas.py`，
采集路由在 `api/data_collection.py`，任务创建在 `services/probe_task_service.py`；
对象身份/覆盖/写入/投影/查询已拆入 `services/data_objects/`。旧 `data_object_service.py` 仅作兼容门面，
不要向其中新增实现。前端入口是 `modules/data-security/DataAssetHub.vue` 与其
`composables/`，页面只做组装；边界由 `tests/test_data_asset_boundaries.py` 检查。

## API 域路由边界

`app/api/` 共 43 个模块。路由只做鉴权、分页与响应结构，判定与计算都在对应服务里；每个域都有
`tests/test_*_boundaries.py` 冻结路径/方法、禁止复制共享守卫、并断言全应用无重复注册。
**改任何一条路径前先跑对应边界测试。**

- **聚合**：`v1.py`。
- **会话**：`auth.py`（`POST /auth/login|logout`、`GET /auth/me`）——会话存储、Cookie 与口令校验仍在
  `core/security.py` 与 `AdminSession`；`/auth/me` 的非生产快捷分支属既有契约，不要改。
- **健康**：`health.py`（`GET /health`）——Redis/Celery 队列深度走 `task_dispatch.queue_depth`，
  worker 能力与规则清单走 `api/runtime_status.py`（与 `/integrations` 共用），探针行形状走
  `api/probe_presenter.py`；`main.py` 对 `/api/v1/health` 的免鉴权放行是既有契约。
- **告警**：`alerts.py`——抑制状态、命中聚合与投递在 `services/alert_service.py`。
- **任务 / 审计 / 报表**：`tasks.py`、`reports.py`——停止/删除判定在 `services/task_service.py` 与
  `services/probe_task_service.py`；报告构建/渲染在 `services/report_service.py`。
- **平台资产**：`assets.py`——行序列化导出为 `serialize_asset` 供其他读域复用；关联判定与评分在
  `services/asset_service.py`、`incident_engine`；`/assets/{id}` 的检测/事件/IOC 行复用共享 presenter。
- **网络资产**：`network_assets.py`（`/network/assets`、`/network/assets/summary`）。
- **数据目录与实例**：`data_catalog.py`（`/data-types*`、`/data-objects*`、`/asset-instances*`、
  `/detections/{id}/evidence`、`/sensitivity-levels`、三个 `/admin/*` 维护端点）。
- **数据资产**：`data_assets.py`（`/data/assets*`、`/sensitive/findings`）与数据目录是两套边界，不要混。
- **数据采集**：`data_collection.py`（探针侧 `/probes/{id}/data-assets*`）。
- **PCAP**：`pcaps.py`（18 条：上传、列表/详情/分析、包/流、协议/流量、DNS/HTTP/TLS、提取清单/预览/下载、抓包告警）。
- **文件证据**：`files.py`（5 条）；PCAP 内提取文件的预览/下载是另一套路径，仍在 `pcaps.py`。
- **探针**：`probes.py`（9 条，含 `POST /probes/register`、心跳、`/crypto/probe-profile`）。
- **探针下发/回收**：`deployments.py`（前缀 `/api/v1/probe-deployments`，main.py 直挂）。
- **扩展命令与情报**：`extensions.py`（`/probes/{id}/scan-jobs|commands|command-status|inventory`、
  `/intelligence/*`、`/dlp/policy`、`/dlp/transfers*`、`/egress/policy`）。
- **集成与离线导入**：`integrations.py`（11 条，含 `/offline/*`、`/offline/grype/*`）——
  适配器元数据与执行走 `app.integrations`，离线包解析走 `app.integrations.offline_manager`，
  Grype 库在 `services/grype_library.py`。
- **DLP 规则库**：`libraries.py`（`/dlp/rules*`，main.py 直挂）；敏感数据（DLP）规则是与检测引擎规则不同的规则族。
- **规则集下发**：`rulesets.py`（`/rulesets*`、`/probes/{id}/ruleset*`，main.py 直挂）。
- **策略分组与指纹**：`policy_groups.py`（`/policy-groups*`、`/fingerprint-candidates*`）。
- **扫描配置**：`profiles.py`（`/scan-profiles*`，main.py 直挂）+ `network_scan.py`（`POST /scan`、`GET /scan/{task_id}`）。
- **评估**：`assessments.py`（`/assessments/{overview,classification,exposure,flow,egress,compliance}`）——
  实现在 `services/assessments/`。
- **目标浏览/测试**：`targets.py`（`/targets/test`、`/targets/browse`）。
- **文件来源**：`file_sources.py`（`/file-sources*`）——实现在 `services/file_scan/`。
- **数据库直连盘点**：`database_connections.py`（11 条）——实现在 `services/database_scan/`。
- **Dashboard 与流量视图**：`dashboard.py`（20 条）——数字必须由 `app/models.py` 的行**实时聚合**，
  不得落库缓存或写死；协议分层复用 `services/protocol_service.py::protocol_layer`。大屏与驾驶舱共用
  `GET /dashboard/overview`（驾驶舱字段是同一响应里的附加块），所以在同一时刻两页不可能对不上数字；
  新增指标要加进这份 overview，不要再开只给驾驶舱用的汇总接口。健康度、合规进度与流向汇总只有一份实现：
  `services/cockpit_service.py`；流向分类走 `services/egress_regions.direction_of`。
- **手动测试数据**：`test_data.py`（`POST /test/import|clear`、`GET /test/status`）——写入口的 opt-in 守卫
  `_require_test_data_import`（读 `settings.test_data_import_enabled`，默认关闭）随域下沉，两个写入口都必须先过
  这个守卫，不得绕过或复制。
- **跨域工具**：`pagination.py`、`query_filters.py`、`list_sort.py`、`dependencies.py`、`error_handlers.py`、
  `runtime_status.py`、`data_collection_schemas.py`、`*_presenter.py`（无路由）。

## 数据流动与出境判定

- 流向只有三类：内部流量 / 外部流出 / 目的未识别。库里**没有 zone 表，所以没有「跨域访问」这一档**，
  不要为了版式补一个。`external` 只在地区表命中或黑名单命中时才成立；未证实的目的地一律 `unknown`（黄），
  不得当成出境（红）。举例：`172.23.0.4` 是私网，必须判 `internal`。
- 实时事件列表读 `GET /alerts?order=recent`（`recent` = `last_seen desc, id desc`）；`order` 默认仍是 `risk`，
  既有列表顺序属兼容边界，不要改默认值。
- 大屏图上是**拓扑**而不是攻击地图：中心是流量最大的内部节点，内部节点在内环、外部端点在外环，线是真实会话对。
  点节点出抽屉（资产信息 / 流量数量 / 风险事件）。`modules/dashboard/components/TrafficMap.vue` 自己持有
  ResizeObserver——面板在拿到数据前是 hidden 的，echarts 会以 100×100 初始化，**少了这个 observer 整张拓扑会画进一个角里**。
- 回归：`frontend/src/__tests__/dashboard-screen-state.test.ts`、`dashboard-screen.test.ts`、
  `dashboard-cockpit.test.ts`、`dashboard-cockpit-state.test.ts` + `vue-tsc` + 全量 vitest；
  后端 `backend/tests/test_dashboard_screen_api.py`、`test_dashboard_boundaries.py`、`test_cockpit_api.py`、
  `tests/test_alerts.py::test_alert_list_orders_by_time_when_recent_is_requested`。

## 探针边界

- 探针以只读、非侵入方式工作：旁路采集，不解密 TLS，不做串接阻断。
- 探针安装路径固定：代码 `/opt/data-security-toolbox`、配置 `/etc/data-security-toolbox`、
  运行数据 `/var/lib/data-security-toolbox`（`spool/` `rules/` `cache/`），systemd 单元 `data-security-toolbox-probe`。
- **探针与服务端的职责边界不可改**：探针只做采集/上传/心跳/受控命令，不做风险评分、告警关联、报告生成。
  OCR 与红头/涉密判定是服务端能力，**探针不做 OCR**。
- 探针鉴权走 `core/security.py` 与 `api/dependencies.py`；登记入册走 `deployment/enrollment.py`；
  删除记录与远端卸载走 `services/probe_service.py`、`deployment/removal.py`；队列派发统一走
  `api/dependencies.py::dispatch_task`。边界由 `tests/test_probe_boundaries.py` 检查。
- 分发包由 `scripts/build_probe_packages.py` 生成到 `probe_packages/probe-<版本>/<arch>/`。

## 配置与账号

- 配置与密钥都在仓库根目录 `.env`（gitignored，模板见 `.env.example`）。管理账号 `admin`，
  口令取自 `.env` 的 `ADMIN_PASSWORD`；**不要把口令或密钥写进任何被 git 跟踪的文件。**
- 探针回连地址由部署时的 `DEPLOYMENT_BACKEND_URL` 决定（探针部署到哪台设备，就用那台能访问到的平台地址）；
  凭据加密密钥 `DEPLOYMENT_SECRET_KEY` **不可随意更换**，否则已存凭据按错误处理。

## 禁止修改的内容

1. **不要在生产控制台导入测试数据**：`POST /api/v1/test/import` 会写入演示用文件/PCAP。
   交付与演示环境要求数据全部真实，禁止调用（`/test/status` 可用于自检）。
2. **不要在生产构建开启 mock**：`VITE_DEMO_MODE=true` 会让前端走 `src/mocks/` 假数据，
   仅限 `npm run dev:demo` / `build:demo` 使用。
3. **不要扩大 `probe/uninstall.sh` 的删除白名单**：删除目标必须来自脚本内固定常量，
   不得读取命令行参数或目标机上的文件（以 root 读可变文件等于提权原语）；符号链接只删链接本身。
4. **不要改动探针与服务端的职责边界**（见“探针边界”）。
5. **不要修改已发布的 Alembic 迁移**，也不要手改线上库结构。
6. **不要绕过 `storage_guard` 另写删除逻辑**，也不要删 `deploy-data/`。
7. 不要用 `git commit` 之外的方式改写历史；不要回滚用户未提交的修改。

## 重要约束

- **主机地址不要写死在文档或代码里**：平台与探针的地址随交付环境变化（本机开发栈用
  `127.0.0.1:8000` / `:8080`），当前交付环境的主机与在线探针以 `PROJECT_STATUS.md` 和实测为准。
  操作任何真实探针主机前先确认，不要凭历史记录动手。
- `apply_patch` 需要与文件行尾一致（本仓库主要文件为 LF；`backend/` 下部分文件为 CRLF），补丁分块尽量小。

## 与其他文档的关系

- 架构与设计：`docs/architecture.md`；部署：`docs/deployment.md`、`docs/部署与运行手册.md`、
  `docs/offline-deployment.md`；验收：`docs/acceptance_test.md`。
- 发布记录：`CHANGELOG.md` + `docs/releases/v<版本>.md`（每个版本一篇，含指纹与验证结论）。
- 数据资产开发入口：`docs/数据资产开发入口.md`。
- 本文件只写长期稳定信息；版本发布、批次改造、临时结论写进 `TASK.md` / `PROJECT_STATUS.md` / `docs/releases/`。
