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
- 路由按域拆分注册：`app/api/v1.py`（主体）、`extensions.py`、`data_catalog.py`、`deployments.py`、
  `libraries.py`、`profiles.py`、`rulesets.py`。
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
不要向其中新增实现。前端列表与采集状态分别在 `modules/data-security/composables/useDataAssetList.ts`
和 `useDataAssetCollection.ts`，页面负责组装。边界由 `tests/test_data_asset_boundaries.py` 检查。

## 分析编排与任务入口

分析与事件关联编排在 `application/analysis.py`，不在 worker 里；任务行持久化在 `services/task_service.py`，
队列派发统一走 `services/task_dispatch.py`（按注册名，broker 不可用才回退本进程）。
worker 任务按职责分在 `workers/{analysis,notification,maintenance}_tasks.py`，注册名集中在
`workers/task_names.py`，生命周期在 `workers/task_runtime.py`；旧 `workers/tasks.py` 仅兼容门面，不要新增实现。
路由/服务不得导入 `app.workers.*`（端口模块除外）；Celery 任务名、参数顺序与队列路由属兼容边界。
边界由 `tests/test_task_boundaries.py` 检查。

## 与其他文档的关系

- 交付/演示口径：`docs/领导演示方案.md`
- 部署与运行：`docs/部署与运行手册.md`、`docs/deployment.md`、`docs/offline-deployment.md`
- 验收：`docs/acceptance_test.md`、`docs/acceptance_test_report.md`
- 版本策略：`docs/versioning.md`、`CHANGELOG.md`
