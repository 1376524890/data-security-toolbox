# 数据资产探测基线分析（阶段 0）

- 文档版本：2026-09-16，对应平台 2.7.0 / 探针 3.3.1
- 依据：`数据资产探测增量优化_主提示词与分阶段提示词.md` 阶段 0 的 12 项产出要求
- 范围：本文只描述**实施前**的真实状态，不含已完成的新功能声明。文末「未验证事实」列出的条目未在本机实测。
- 标注约定：`文件:行号` 均为本机实测行号（`source/` 为相对根）。

---

## 1. 项目结构与版本

| 项 | 实测值 | 证据 |
|---|---|---|
| 工程相对根 | `00-数据安全工具箱/source` | 目录实测存在 |
| 平台版本 | **2.7.0** | `backend/app/main.py:28`；`CHANGELOG.md`（`d4eb41f chore(release): v2.7.0 - platform 2.7.0, probe 3.3.1`） |
| 探针版本 | **3.3.1** | `probe/probe.py:51` `AGENT_VERSION = "3.3.1"`；`probe_packages/build_packages.py` `VERSION = "3.3.1"` |
| 已构建探针包 | `probe-3.2.0`、`3.2.1`、`3.3.0`、`3.3.1`（各含 amd64/arm64） | `probe_packages/probe-*` |
| 后端技术栈 | FastAPI、SQLAlchemy 2.x、Alembic、PostgreSQL、Redis、Celery | `backend/requirements.txt`、`docker-compose.yml` |
| 前端技术栈 | Vue 3、TypeScript、Element Plus、ECharts、Vite | `frontend/package.json` |
| 探针形态 | Linux Python 常驻程序 + systemd，`requests`/`psutil`；**不是** FastAPI/Celery 服务 | `probe/probe.py`、`probe/requirements.txt`、`probe/data-security-toolbox-probe.service` |
| 部署入口（实测运行） | 前端 `http://localhost:8088`、后端 `http://localhost:8000` | `HTTP_PORT=8088`（`.env`）；`docker ps` 显示 `source-frontend-1 0.0.0.0:8088->80/tcp`、`source-backend-1 0.0.0.0:8000->8000/tcp` |
| 已登记探针（实测） | 1 台：`kali` / `192.168.191.130` / `online` / `agent_version=3.3.1` | `GET /api/v1/probes`，`metadata.system.agent_version` |
| 本机 Docker 服务 | `postgres`、`redis`、`backend`、`worker`、`beat`、`deployment-worker`、`frontend`、`flower`（项目 `source`） | `docker-compose.yml`；`docker ps` |

### 工作树状态（本次改动前）

```
 M .env.example
 M backend/app/api/extensions.py
 M backend/app/core/config.py
 M backend/app/services/dlp_service.py
 M backend/tests/test_dlp_detection_quality.py
 M docker-compose.yml
 M docs/dlp-detection-quality.md
 M frontend/package-lock.json
 M frontend/package.json
```

以上 9 个文件是**上一轮「NetDLP 自流量排除 / 低置信度过滤」修复的未提交修改**（对应已提交的 `fde1149 fix(dlp): alert only on protected data instead of every cleartext stream` 之后的后续调整），与本次数据资产探测改造无关。本次实施**不得 reset、覆盖或丢弃**这些修改；后续每阶段记录需区分「已有修改」与「本次修改」。当前分支 `develop`。

---

## 2. Server 入口、API、Service、Models、Alembic

### 2.1 入口与中间件

- `backend/app/main.py:13-25` lifespan：配置日志；**当 `DATABASE_URL` 以 `sqlite` 开头时执行 `Base.metadata.create_all()`**；初始化管理员。
- `backend/app/main.py:28`：`FastAPI(title=settings.app_name, version="2.7.0")`。
- `backend/app/main.py:30-33`：挂载 4 个 router —— `app.api.v1.router`、`deployments_router`、`extensions_router`、`libraries_router`。
- `backend/app/main.py:44-61` `admin_auth_middleware`：**仅在 `settings.app_env == "production"` 时强制管理端会话认证**；`PUBLIC_PREFIXES`（`/docs`、`/openapi.json`、`/redoc`）与 `_is_probe_api()` 白名单放行。
- `backend/app/main.py:39-43` `_is_probe_api()`：探针路径白名单为
  `/api/v1/probes/register`，以及 `/api/v1/probes/` 前缀下以 `/heartbeat`、`/scan`、`/commands`、`/inventory`、`/data-assets`、`/command-status` 结尾的路径，另有 `/api/v1/pcaps/upload`、`/api/v1/files/upload`、`/api/v1/health`。
  → **新增探针接口仍须经过 `require_probe_headers` 自行校验 probe token**，白名单只跳过管理端会话校验。

### 2.2 目录职责

| 目录 | 职责 |
|---|---|
| `backend/app/api/` | `v1.py`（主业务+平台查询）、`deployments.py`（SSH/SFTP 部署）、`extensions.py`（探针命令/清单/情报/DLP 策略）、`libraries.py`（规则库、离线资源） |
| `backend/app/services/` | 领域服务：`probe_task_service.py`、`dlp_service.py`、`rule_library.py`、`scan_service.py`、`asset_service.py`、`alert_service.py`、`report_service.py` 等 |
| `backend/app/engine/` | 检测流水线：`core/`（`context.py::DetectionContext`、`base.py`、`pipeline.py`、`registry.py`、`result.py`），以及 `data_engine/`、`dlp_engine.py`、`traffic_engine/`、`risk_engine/`、`protocol_engine/`、`asset_engine/`、`compliance_engine/` |
| `backend/app/workers/` | Celery：`tasks.py`、`celery_app.py`、`deployment_tasks.py` |
| `backend/app/deployment/` | SSH/SFTP 部署：`package.py`（包选择+SHA256 校验）、`service.py`、`ssh_client.py`、`credential.py`、`enrollment.py` |
| `backend/app/integrations/presidio/` | Presidio 适配器与 recognizer |
| `backend/app/models.py` | **单文件**声明式模型（450 行），**没有** `models/` 包 |
| `backend/alembic/versions/` | 迁移，线性链 0001→0009，**head = `0009_probe_data_assets`** |

### 2.3 Alembic

```
0001_initial → 0002_engine_upgrade → 0003_v2_1_integrations → 0004_enterprise_platform
→ 0005_v3_continuous → 0006_alert_lifecycle → 0007_file_md5 → 0008_probe_deployments
→ 0009_probe_data_assets
```

`0009` 只做一件事：给 `probe_deployments` 增加 `data_config` JSON 列（幂等 `_column_exists` 守卫）。本次新增表应从 `0009_probe_data_assets` 继续。

> **风险 R1（重要）**：`main.py:22-23` 在 SQLite 下用 `create_all()` 建表，而生产用 Alembic。任何新模型若只改 `models.py` 不改迁移，SQLite 测试与 PostgreSQL 生产会出现**结构性偏差**，且「空库迁移」测试无法发现。本次每张新表、每个新列**必须同时**改 `models.py` 与新增 Alembic 迁移，并做 PostgreSQL 升级验证。

### 2.4 迁移与历史数据现状（实测）

- 运行中的后端连 PostgreSQL（`source-postgres-1`），平台版本 2.7.0，worker 2 个在线，`analysis_worker=ready`（tshark 4.4.18 / zeek 9.0.0 / suricata 7.0.10）。
- `GET /api/v1/data/assets` 实测 **total = 5**，全部 `source=probe:kali`、`sensitivity=Low`、`asset_type` 为 `file`/`directory`，是历史上一次探针采集留下的兼容投影记录（`data_assets.py`、`probe.py`、`requirements.txt`、`scanner.py`、一个目录）。
- `GET /api/v1/tasks` 最近的 10 条均为 `kind=pcap`、`status=Success`。**当前没有活跃的 `data_asset_scan` 任务**。

---

## 3. Agent 生命周期：注册、心跳、轮询、采集、上传、取消/超时

全部位于 `probe/probe.py`（1045 行）；本地数据发现实现位于 `probe/data_assets.py`（408 行）。

### 3.1 身份与注册

- `probe/probe.py:52` `DEFAULT_CONFIG`：`server`/`capture`/`spool`/`agent`/`scan`/`data` 六段；`agent.identity_path` 默认 `/etc/data-security-toolbox/probe.identity.json`，`spool.path` 默认 `/var/lib/data-security-toolbox/spool`。
- `probe/probe.py:651` `register()` → `POST /api/v1/probes/register`（`probe.py:671`），带 `X-Probe-Bootstrap-Token`；成功后调 `ProbeIdentity.save()`（`probe.py:236`）以 **`0600` + 临时文件 rename 原子落盘**，并 `Config.clear_bootstrap()` 清掉 TOML 里的一次性引导 token。
- 服务端：`backend/app/api/v1.py:621` `register_probe()`，校验 bootstrap token（`security.py`）与部署登记（`ProbeEnrollment` 一次性消费）。
- 兼容要求：原地升级**不得**删除 `probe.identity.json` 或 token，不得要求重新注册。

### 3.2 心跳

- 探针：`probe.py:683` `heartbeat_once()` → `POST /api/v1/probes/{id}/heartbeat`，`metadata` 含 `system`（含 `agent_version`）、`interfaces`、`services`、`capture_status`、`upload_status`；`probe.py:893` `heartbeat_loop()` 周期由 `agent.heartbeat_seconds`（默认 30）控制。
  - 另有两个"顺带心跳"点：`probe.py:851` `file_loop()`（`file_inventory`）、`probe.py:837` `asset_loop()`（`services`）。
- 服务端：`v1.py:684` `heartbeat()`；`v1.py:523` `_merge_metadata()` 做**深合并**，避免并发 loop 互相覆盖 `extra`。
  → 本次「心跳附加 `current_ruleset_version`/`capabilities`」应复用该深合并语义，保持旧探针忽略新字段仍可用。

### 3.3 轮询与命令领取

- `probe.py:968` `inventory_loop()`：**单线程**，5～30 秒（`scan.poll_seconds` / `data.poll_seconds`）轮询一次，最多 1 个受控执行单元。
  - 前置条件：`scan.allow_remote` 或 `data.allow_remote` 为真，或 `scan.enabled`/`data.enabled` 为真，否则该线程**直接不启动**（`probe.py:972-975`）。
  - 领取：`probe.py:916` `_next_command()` → `GET /api/v1/probes/{id}/commands`，取 `commands[0]`，`kind` 为 `asset_scan` / `data_asset_scan`。
  - 分发：`probe.py:956` `_run_data_asset_job()` → `data_assets.discover_data_assets()`；`probe.py:_run_scan_job()` → `scanner.scan_network()`。
- 服务端：`extensions.py:109` `probe_commands()` 在同一事务内用 `with_for_update()` 把 `Pending` 置为 `Running` 并返回，避免重复领取；`COMMAND_KINDS` 映射见 `extensions.py:106`。

### 3.4 报告持久化、上传、重试

- 落盘：`probe.py:902` `_spool_report()` 写 `spool/agent-state/*.pending.json`（**单文件**：`inventory.pending.json`、`data-assets.pending.json`），临时文件 + `os.replace` 原子替换。
- 上传：`probe.py:909` `_upload_pending()` 读取后 `POST /api/v1/probes/{id}/{inventory|data-assets}`，**成功才 `unlink`**；异常由外层 `except` 捕获后保留文件，下轮重试（`probe.py:1006` 打印 `probe inventory upload/scan retry`）。
- 报告 ID：`report_id = uuid4().hex`，随报告一起落盘，保证重试不产生新 ID。
- 报告体：`probe/data_assets.py:305` `discover_data_assets()` 返回 `assets`/`databases`/`scanned_paths`/`counts`/`max_depth`/`complete`/`error`/`observed_at`/`scanner`/`location`/`duration_ms`。
- 服务端幂等：`extensions.py:269` `data_asset_inventory()` 先 `SELECT ... FOR UPDATE` 锁 probe 行，再按 `task_id` 或 `(kind, probe_id, report_id)` 找任务；任务已终态或已逻辑删除则直接返回 `duplicate=True`；领取后 `task.status` 由 `Partial`/`Success`/`Failed` 决定，并写 `AnalysisResult(module='data_assets')`。
- 上传状态机常量（用于 PCAP 上传）见 `probe.py:98-106`：`pending/uploading/uploaded/retry_wait/auth_error/quarantined`，`TRANSIENT_HTTP={429,500,502,503,504}`、`PERMANENT_HTTP={400,413,422}`。

### 3.5 取消与超时

- 协作取消：`probe.py:919` `_job_stop_event()` 返回一个 `JobStop` 对象，`is_set()` 每 3 秒调用一次 `GET /api/v1/probes/{id}/command-status?task_id=...`，服务端返回 `stop=True` 即停止。**不 kill 进程**。
- 服务端：`extensions.py:128` `command_status()` 返回 `{'stop': task.status in TERMINAL or task.payload.get('deleted')}`。
- 超时：`backend/app/services/probe_task_service.py:17` `expire_probe_tasks()` —— `Pending` 超过 **900 秒**未领取、`Running` 超过 `config.timeout_seconds + 120` 秒未回传，均置 `Failed` 并写 `error`。由 Celery beat 任务 `backend/app/workers/tasks.py:867` `expire_remote_probe_tasks` 周期调用，也在每次 `commands`/`command-status`/入队请求中先行调用。
- 终态集合：`probe_task_service.py:11` `TERMINAL = ('Success','Failed','Partial','Cancelled')`。

### 3.6 抓包与 NetDLP（平台侧，探针不参与检测）

- 探针 `probe.py:717` `capture_loop()` 用 `dumpcap`/`tcpdump` 分段抓包；`probe.py:802` `upload_loop()` 负责上传；`probe.py:851` `file_loop()` 在 `agent.file_interval_seconds>0` 且配置了 `agent.paths` 时才会上传**原始文件**（既有显式配置能力，本次**不得自动开启**）。
- 服务端 `workers/tasks.py:510` `analyze_pcap_task()` → 注册表 `dlp_engine` → `backend/app/engine/dlp_engine.py` → `backend/app/services/dlp_service.py:364` `analyze_capture()`。
- NetDLP 文本识别入口：`dlp_service.py:335` `inspect_content()`，**当前直接 import `app.engine.data_engine.engine.REGEX_RULES`**（`dlp_service.py:338`），并使用 `BUILTIN_CONFIDENCE`（`dlp_service.py:37`）+ `rule_library.scan_managed()`（`rule_library.py:167`）。
  → 这正是阶段 1 需要收敛为「共享引擎」的分叉点之一。

---

## 4. Presidio：运行时与静态导入是两条不同的路径

实测结论：**存在两套并存、互不感知的 Presidio 相关路径**，且当前环境 Presidio 运行时默认关闭。

| 维度 | 静态导入（规则库） | 运行时识别 |
|---|---|---|
| 入口 | `POST /api/v1/dlp/rules/presidio/update`（`libraries.py:49`） | `DETECTION` 引擎 `data_engine`、`presidio` adapter |
| 实现 | `rule_library.update_presidio()`（`rule_library.py:153`）→ `import_presidio_wheel()`（`rule_library.py:111`） | `integrations/presidio/recognizers.py:52` `presidio_scan()` |
| 机制 | 下载 PyPI wheel，用 `ast` **静态解析** `predefined_recognizers/*.py` 里的 `Pattern(name, regex, score)` | `from presidio_analyzer import AnalyzerEngine` 真正跑 NLP 分析 |
| 产物 | `data/integrations/dlp_rules/presidio.json`，规则 `source='Presidio'`、`id='presidio-<sha256[:24]>'` | 内存中的 `AnalyzerResult` 列表 |
| 缺省启停 | `rule['enabled'] = current.get(id, confidence >= MIN_ALERT_CONFIDENCE(0.6) and sensitive_entity(rule))`（`rule_library.py:140`） | 受 `settings.presidio_enabled` 控制；**`docker-compose.yml` 中 `PRESIDIO_ENABLED: "false"`** |
| 依赖模型 | 不需要 NLP 模型，不需要 `presidio_analyzer` | 需要 `presidio_analyzer`，可选依赖见 `backend/requirements-optional.txt` |

关键点：

1. `rule_library.py` 文档化的导入范围明确写着「Presidio 静态正则模式；不包含 NLP 模型、上下文评分或 Python 校验器」。**当前没有任何 `rule_source=presidio_static` 之类的来源标记**，也没有把「静态正则命中」与「运行时 recognizer 命中」在 evidence 上区分开。
2. `integrations/presidio/adapter.py` 的 `adapt()` 会在 `parse()` 返回空时回退到 `fallback_scan()`，并把 `source` 写成 `"presidio"` 或 `"regex-fallback"`（该判断用 `records != fallback_scan(text)` 比较，属于**不可靠的启发式**），evidence 中还会带 `samples`（原文片段）。
3. `data_engine.engine.py:118` `presidio_scan()` 在 `settings.presidio_enabled=False` 时直接返回 `[]`，异常也返回 `[]`——**吞掉错误**，无法区分「未启用」「缺依赖」「执行出错」。
4. 服务端 `data_engine` 会把匹配到的**原文样本**写进 `evidence`（`data_engine/engine.py:57` `scan_text()` 返回 `samples`，`samples` 随 finding 入库）。这与本次「报告/证据不得携带原值」的目标直接冲突，属于必须改造项。

---

## 5. 真实数据模型与可复用能力

`backend/app/models.py` 现有 26 个模型。与本任务相关的：

| 模型 | 可复用点 | 缺口 |
|---|---|---|
| `Probe` | `token`/`token_hash`、`last_seen`、`extra`(JSON) 深合并、`deployment_id` | 无 `capabilities`、无 `current_ruleset_version` 结构化字段（目前塞在 `extra`） |
| `Task` | **通用任务载体**：`kind`/`status`/`progress`/`current_stage`/`payload`/`result`/`error`/`started_at`/`finished_at` | 无 `scan_id`、无规则/引擎/Profile 版本快照、无覆盖率与终止原因字段 |
| `DataAsset` | 旧页面/API 的兼容投影目标：`name`/`asset_type`/`sensitivity`/`source`/`columns`(JSON)/`extra`(JSON) | 是**扁平投影**，无对象/实例/检测层级 |
| `FileRecord` | `sha256`/`md5`/`file_type`/`metadata_json` | md5 是后期补列（`0007_file_md5`） |
| `Asset` | 主机/服务资产，含 `probe_id` | 与文件数据资产无关联 |
| `DetectionFinding` | 平台统一 finding 表（`engine`/`rule_id`/`severity`/`confidence`/`evidence`/`risk_*`） | 是**网络/平台 finding**，不是"某实例上某敏感类型的汇总 Detection" |
| `AnalysisResult` | 任务级结果快照 | 无结构 |
| `Alert`/`Incident` | 告警/事件链路，P1 RiskEngine 的落点 | P0 不新建风险工作流 |
| `GraphRelation` | 通用关系表（`source_node/type`、`target_node/type`、`relation`、`risk`） | 无 `confidence`/`evidence_type`/规则版本；P1 应评估扩展而非新建等价模型 |
| `SystemSetting` | KV 配置（`key` 唯一 + `value` JSON） | 可用于集中配置分类分级映射 |
| `ProbeDeployment` 系列 | 部署登记、一次性 enrollment、凭据加密、事件流 | 与规则/Profile 分发无关 |

已确认**完全不存在**的概念：`RuleSet`、`Rule`、`RuleVersion`、`ScanProfile`、`DataObject`、`AssetInstance`、`Detection`（作为实例级汇总）、`DetectionEvidence`。

可直接复用的既有机制（不得重写）：

- 探针认证：`backend/app/core/security.py::require_probe_headers`（`X-Probe-ID` + `X-Probe-Token`）。
- 任务生命周期与超时：`probe_task_service.py`。
- 报告幂等 + 行锁串行化：`extensions.py:139`/`extensions.py:269` 的 `with_for_update()` 模式。
- 逻辑删除：`Task.payload['deleted']` + `visible_tasks()`（`probe_task_service.py:14`）。
- 探针删除保护：未完成任务阻止删除（`v1.py:718` `delete_probe` 相关测试 `tests/test_probe_delete.py`）。
- 包分发与校验：`deployment/package.py::find_package()`（manifest + 实际字节 SHA256 复核）。
- 部署通道：`deployment/service.py` + `ssh_client.py`（SFTP 上传 + 远端 `install.sh`）。

---

## 6. 相关 API 清单（实测 Method / Path / Handler）

认证列含义：`admin` = 管理端会话（生产由中间件强制）；`probe` = `X-Probe-ID`/`X-Probe-Token` 校验。

| Method | 完整 Path | Handler | File:Line | 认证 | 用途 |
|---|---|---|---|---|---|
| POST | `/api/v1/probes/register` | `register_probe` | `v1.py:621` | bootstrap token | 探针首次注册 |
| POST | `/api/v1/probes/{probe_id}/heartbeat` | `heartbeat` | `v1.py:684` | probe | 心跳 + metadata 深合并 |
| GET | `/api/v1/probes` | `list_probes` | `v1.py:707` | admin | 探针列表 |
| DELETE | `/api/v1/probes/{probe_id}` | `delete_probe` | `v1.py:718` | admin+role | 删除探针（未完成任务阻止） |
| GET | `/api/v1/probes/{probe_id}/commands` | `probe_commands` | `extensions.py:109` | probe | 领取本地任务（`FOR UPDATE` 置 Running） |
| GET | `/api/v1/probes/{probe_id}/command-status` | `command_status` | `extensions.py:128` | probe | 协作取消查询 |
| POST | `/api/v1/probes/{probe_id}/inventory` | `inventory` | `extensions.py:139` | probe | 资产扫描报告入库 |
| POST | `/api/v1/probes/{probe_id}/scan-jobs` | `queue_scan` | `extensions.py:98` | admin | 下发资产扫描 |
| POST | `/api/v1/probes/{probe_id}/data-assets/jobs` | `queue_data_asset_scan` | `extensions.py:246` | admin | 下发数据资产采集（**旧创建入口**） |
| POST | `/api/v1/probes/{probe_id}/data-assets` | `data_asset_inventory` | `extensions.py:269` | probe | 数据资产报告入库（幂等） |
| GET | `/api/v1/data/assets` | `data_assets` | `v1.py:1744` | admin | 旧数据资产列表（分页/筛选） |
| GET | `/api/v1/data/assets/{data_asset_id}` | `data_asset_detail` | `v1.py:1761` | admin | 旧数据资产详情 + finding + pii_summary |
| GET | `/api/v1/sensitive/findings` | `sensitive_findings` | `v1.py`（`/sensitive/findings`） | admin | 敏感发现聚合（当前只读 `DetectionFinding` + `DataAsset`） |
| GET | `/api/v1/dlp/rules` | `list_dlp_rules` | `libraries.py:23` | admin | 旧规则入口（builtin + 人工 + presidio 静态） |
| POST | `/api/v1/dlp/rules` | `add_dlp_rule` | `libraries.py:41` | admin | 新增人工规则 |
| PATCH | `/api/v1/dlp/rules/{identifier}` | `set_dlp_rule` | `libraries.py:61` | admin | 启停规则 |
| POST | `/api/v1/dlp/rules/presidio/update` | `download_presidio` | `libraries.py:49` | admin | Presidio 静态规则导入 |
| GET | `/api/v1/dlp/policy` | `dlp_policy` | `extensions.py:457` | admin | NetDLP 策略 |
| GET | `/api/v1/tasks`、`/tasks/{id}`、`POST /tasks/{id}/stop`、`DELETE /tasks/{id}` | — | `v1.py:1219-1263` | admin | 通用任务中心（旧页面在用） |
| GET | `/api/v1/health` | `health` | `v1.py:563` | 公开 | 健康与 worker 能力 |

> `POST /api/v1/probes/{probe_id}/data-assets/jobs` 已存在版本门控：仅当 `probe.extra.agent_version < 3.3.0` 时返回 409（`extensions.py:250-254`），门控依据是**版本号字符串**，不是 capabilities。

---

## 7. 两条独立流程与原始数据边界

### 7.1 流程 A：文件数据资产采集（本次改造对象）

```
[管理员] POST /probes/{id}/data-assets/jobs ──> Task(kind=data_asset_scan, status=Pending)
                                                      │
[探针 inventory_loop] GET /probes/{id}/commands ──────┤ (FOR UPDATE: Pending→Running)
                                                      ▼
                      job.kind == "data_asset_scan" ──> _run_data_asset_job()
                                                      │
                        discover_data_assets(merged, stop_event)   ← 本地有界扫描
                          · os.walk 深度/文件数/目录数/时间限制（data_assets.py:305）
                          · 正则匹配 SENSITIVE_RULES（data_assets.py:41）在**内存中**
                          · CSV/SQL/JSON 列推断（infer_columns）
                                                      │
                                      写入 spool/agent-state/data-assets.pending.json（原子）
                                                      │
[探针] POST /probes/{id}/data-assets ─────────────────┤ 成功 → unlink；失败 → 保留重试
                                                      ▼
                      data_asset_inventory(): FOR UPDATE → upsert DataAsset(投影)
                        · complete && !error 时，对 scope 内未发现项标 status=not_observed
                        · task.result / AnalysisResult(module=data_assets) / probe.extra.last_data_asset_scan
                                                      │
[页面] GET /data/assets、/data/assets/{id}、/sensitive/findings
```

**原始数据边界（现状）**

| 环节 | 是否离开主机 | 说明 |
|---|---|---|
| 文件内容读取 | 否 | 只在探针内存中取样分析（`SCAN_LIMIT=2MiB`，`data_assets.py` 顶部常量） |
| 正则匹配值 | 否 | `scan_text()` 只返回**计数**（`data_assets.py:78`），样本值不外传 |
| 列名/列类型/列计数 | **是** | `columns[].name` 与 `count` 进报告；列名本身可能是敏感信息（如 `id_card`），需按提示词做长度/结构约束 |
| SHA256 | 是 | `_sha256()`，`>8MiB` 返回空串（`data_assets.py:189` `HASH_LIMIT`） |
| 目录/文件路径 | 是 | `path` 明文上传（`__directory_asset`/`inspect_file`） |
| 数据库服务探测 | 是 | 仅端口连通性 + 引擎名（`detect_local_databases`） |
| **服务端落库** | — | `DataAsset.columns`/`extra` 原样存 JSON；`extra.evidence` 含 `extension`/`scanned_bytes`/`read_error` |

### 7.2 流程 B：PCAP 采集与 NetDLP（**保持不动**）

```
[探针] capture_loop(): dumpcap/tcpdump 分段写本地 seg_*.pcap
        │  成功 → POST /api/v1/pcaps/upload（原始 PCAP 字节上传）
        ▼
[平台] PcapRecord 入库 → Celery analyze_pcap_task (tasks.py:510)
        │
        ├─ protocol_service.parse_pcap → Flow/PacketRecord/Anomaly（tshark）
        ├─ traffic_engine / risk_engine / incident_engine / alert_service
        └─ dlp_engine → dlp_service.analyze_capture(path, policy)
                 · 重组 TCP 流（MAX_STREAM 2MiB / MAX_TOTAL 32MiB / MAX_STREAMS 256）
                 · 排除内网流、自流量（DLP_IGNORE_OWN_TRAFFIC 未提交改动）
                 · http_objects() 提取对象 → inspect_content() 文本识别
                 · policy.min_confidence 过滤后生成 DLP_TRANSFER_001 finding
```

**边界差异（必须如实说明）**：流程 B 会把**原始 PCAP 上传到平台**并在服务端做检测，因此"任何原始数据都不出主机"这一表述**只适用于本次新增/改造的文件数据资产链路**，不适用于既有抓包架构。提示词已明确：保留既有 PCAP 上传与 NetDLP 链路，不宣称历史系统已满足该性质。

### 7.3 两条流程的交叉点

1. `dlp_service.inspect_content()`（`dlp_service.py:335`）与 `data_engine.engine.scan_text()`（`data_engine/engine.py:57`）**各自维护一份正则**，而 `probe/data_assets.py:41` 的 `SENSITIVE_RULES` 是**第三份**。同一敏感类型当前有三套实现，规则语义已经出现差异：

| 类型 | `probe/data_assets.py` | `engine/data_engine/engine.py` | `dlp_service` 置信度 |
|---|---|---|---|
| phone | `(?<!\d)1[3-9]\d{9}(?!\d)` | 同 | 0.7 |
| id_card | 同 | 同 | 0.9 |
| bank_card | 同 | 同 | 0.85（**无 Luhn 校验**） |
| email | 同 | 同 | 0.85 |
| api_key | 同 | 同 | 0.95 |
| token | 同 | 同 | 0.3 |
| 列名提示 | `COLUMN_HINTS`（9 类，含 name/address/user_id/medical_record/credential） | `infer_columns` 内联 4 类映射 | 无 |

→ 阶段 1 必须收敛为单一共享实现，并保留旧输出形态适配器。

---

## 8. P0 / P1 / P2 对照（Existing / Missing / Modify / Add）

### P0（本次必须完成）

| 能力 | 状态 | 说明 |
|---|---|---|
| 共享 SensitiveDetectionEngine | **Missing** | 现有 3 份正则分叉（见 7.3） |
| RuleSet / Rule / RuleVersion + 不可变发布 + Manifest + 热更新 | **Missing** | 现有只有文件系统 JSON（`data/integrations/dlp_rules/*.json`）+ `rule_library.py` |
| ScanProfile（版本化扫描配置） | **Missing** | 现在只有 `DataAssetScanConfig`（`extensions.py:186`）与 TOML `[data]` 段 |
| ScanBudget / LargeFileSampler / 有界解析器（CSV/TSV/JSON/JSONL/SQL/SQL.GZ/XLSX） | **Missing**（部分 **Modify**） | 现有 `_read_text()` 只读**头部** 2MiB，无多点采样；XLSX 只在服务端 `data_engine.extract_text()` 用 openpyxl 读整本（**无界**，`data_engine/engine.py:39-50`） |
| 增量缓存 | **Missing** | 无 |
| DataObject / AssetInstance / Detection / DetectionEvidence | **Missing** | 需新增表 + 迁移 |
| ACTIVE / NOT_OBSERVED 生命周期 | **Modify** | 现有用 `DataAsset.extra.status = observed/not_observed`（字符串），范围判断写在 `extensions.py:295-305`，不是独立实例表 |
| 任务进度（文件数/字节/当前路径） | **Missing** | 现有只有 0→100 的粗粒度 `progress` + `current_stage` |
| capabilities 能力协商 | **Missing** | 现在靠版本号字符串判断（`extensions.py:250`） |
| 平台对象/实例/检测查询 API | **Missing** | — |
| 旧 `DataAsset` 兼容投影 | **Modify** | 已有投影写入逻辑，需保留并可继续工作 |
| 数据类型中心/详情、对象详情、实例详情、Profile/任务/规则页面 | **Missing** | 现有 `/data-assets`（`frontend/src/modules/data-security/DataAsset.vue`）是旧扁平列表 |
| 报告安全序列化 + 服务端二次校验 | **Missing** | 现在 `evidence` 可含原文样本（`data_engine/engine.py:57`） |

### P1（只留设计与扩展点，本次不实现）

- AssetRelation 增强、静态↔网络数据类型关联、DataFlow、RiskEngine 新工作流、网络关联页面。
- 设计落点：**优先扩展已有 `GraphRelation`** 与 `Alert`/`Incident`/`DetectionFinding` 链路，而不是新建同名等价模型。关系字段需补 `source_type/source_id/target_type/target_id/relation_type/confidence/evidence_type/observed_at/ruleset_version`。
- 约束：同一主机同敏感类型的静态与网络命中只能形成**主机级候选关联**（`POSSIBLY_RELATED_TO`），不能证明具体文件是传输来源。

### P2（只做规划）

- 数据库元数据采集、表/列敏感识别、应用与数据库关系。
- 保留 `DatabaseCollector`/`DatabaseParser`/`AssetAdapter` 的**接口位置**；当前只保留已有本地数据库服务端口探测（`detect_local_databases`），不新增全库扫描、不接收数据库口令。

---

## 9. 文件级实施计划与分发方案

### 9.1 新增共享库（唯一检测语义来源）

```
shared/sensitive_detection/__init__.py
shared/sensitive_detection/context.py      # SensitiveDetectionContext（独立于 engine.core.context.DetectionContext）
shared/sensitive_detection/result.py       # DetectionHit / Evidence（不含匹配值）
shared/sensitive_detection/entities.py     # 规范实体名 + alias 映射 + 分类分级 + 来源枚举
shared/sensitive_detection/validators.py   # builtin 允许名单：Luhn、身份证日期/校验位、邮箱
shared/sensitive_detection/confidence.py   # 版本化置信度计算
shared/sensitive_detection/rules.py        # 内置规则声明（JSON 可序列化）
shared/sensitive_detection/engine.py       # 引擎：Regex/Keyword/FieldName/Context/Validator + 超时/长度/数量上限
shared/sensitive_detection/ruleset.py      # 规则包加载/校验/版本（阶段 2 复用）
```

约束：**不得** import FastAPI / SQLAlchemy / Celery；文本只入内存；正则统一走 `regex` 库超时（沿用 `rule_library.scan_managed` 的 `timeout=.05` 做法）；禁止 eval/exec/远程 Python。

### 9.2 新增探针侧文件

```
probe/ruleset_client.py   # 有界下载 → SHA256 校验 → schema/版本检查 → 临时引擎 → 有界自测 → 原子切换
probe/scan_budget.py      # ScanBudget：monotonic 时间、共享计数、协作取消、分块检查
probe/fingerprint.py      # 完整 SHA256 + PARTIAL_FINGERPRINT（HEAD/25/50/75/TAIL）
probe/sampling.py         # LargeFileSampler：文本多点采样、CSV/TSV 记录级、SQL、JSON/JSONL、SQL.GZ
probe/scan_cache.py       # SQLite 增量缓存（只存元数据/Hash/Detection 汇总）
probe/parsers/{__init__,generic_text,csv_tsv,json_like,sql,xlsx,magic}.py
probe/scan_profile.py     # Profile 解析 + 兼容旧 TOML/config
```

需同步修改：`probe/probe.py`（心跳能力、规则版本、进度上报、任务快照、单 pending→有界队列）、`probe/data_assets.py`（改为调用共享引擎与 parsers）、`probe/install.sh`、`probe/requirements.txt`、`probe/probe.toml.example`、`probe/data-security-toolbox-probe.service`（`ReadWritePaths` 需覆盖规则状态目录）。

### 9.3 新增后端文件

```
backend/app/models_data_discovery.py       # 或在 models.py 内追加（沿用现有"单文件模型"风格）
backend/alembic/versions/0010_*.py         # 规则与 Profile
backend/alembic/versions/0011_*.py         # 对象/实例/检测/证据
backend/app/services/sensitive_engine.py   # 共享引擎适配器 + 平台侧调用封装
backend/app/services/report_guard.py       # 报告字段白名单校验（探针侧同源实现复用）
backend/app/services/ruleset_service.py    # 发布/Manifest/包/回滚
backend/app/services/scan_profile_service.py
backend/app/services/data_object_service.py# 对象聚合 / 实例 upsert / Detection 合并 / scope 生命周期
backend/app/api/data_discovery.py          # 新 P0 API（挂载到 /api/v1）
backend/app/services/classification.py     # L1~L4 ↔ Critical/High/Medium/Low 可配置映射
```

### 9.4 分发与 Docker 导入方案（关键）

现状：探针包由 `probe_packages/build_packages.py` 的 `FILES` 列表**显式枚举**（`install.sh`/`probe.py`/`scanner.py`/`data_assets.py`/`requirements.txt`/`service`），`install.sh` 也用显式 `cp` 列表拷贝。

因此共享库必须同时解决 4 条路径，否则"只在开发目录能 import"：

1. **探针包**：`build_packages.py` 需把 `shared/sensitive_detection/` 打包为包内目录（例如 `shared/sensitive_detection/`），`install.sh` 需拷贝到 `${APP_DIR}/shared/`，并在 `probe.py` 顶部加入 `sys.path`（或 package `__init__`）解析，同时保证 `from .data_assets import ...` 与顶层 `from data_assets import ...` 两种导入方式都不破。
2. **后端 Docker build context**：`docker-compose.yml` 中 backend/worker/beat/deployment-worker 的 `build.context` 目前是 `./backend`，共享库在 `source/shared/`，**不在 context 内**，必须改为 `context: .` + `dockerfile: backend/Dockerfile`（或把 `shared` 复制进 backend），否则镜像构建时 import 失败。
3. **远端安装**：`deployment/service.py` 通过 SFTP 上传包内容并调 `install.sh`；`package.py::find_package()` 会用 `manifest.json` 的 `files` 列表检查文件是否齐全 —— 新增目录式文件后，manifest 的 `files` 语义需要扩展（目录/前缀）。
4. **依赖**：`probe/requirements.txt` 需增加 `regex`（`scan_managed` 已依赖，但探针 requirements 中没有）；`openpyxl` 作为**明确的可选/锁定依赖**，缺失时必须降级为 `xlsx_parser=false` 并在能力与 UI 上如实展示。

### 9.5 前端文件

```
frontend/src/types/dataDiscovery.ts
frontend/src/api/dataDiscovery.ts
frontend/src/modules/data-security/SensitiveTypes.vue      # 类型中心
frontend/src/modules/data-security/SensitiveTypeDetail.vue # 类型详情
frontend/src/modules/data-security/DataObjectDetail.vue    # 对象详情
frontend/src/modules/data-security/AssetInstanceDetail.vue # 实例详情
frontend/src/modules/data-security/ScanProfiles.vue        # Profile 管理
frontend/src/modules/data-security/ScanTaskDetail.vue      # 任务进度/结果
```

`frontend/src/router/index.ts` 需新增路由并保留 `/data-assets` 旧入口；`frontend/src/router/menu.ts` 需在已有分组下挂载，不新增顶级分组。未接入的 P1/P2 统计位显示"尚未接入"，不得填 0 冒充已实现。

---

## 10. 兼容风险清单

| 编号 | 风险 | 影响 | 处置 |
|---|---|---|---|
| R1 | SQLite `create_all` 与 Alembic 双轨（见 2.3） | 新表在测试可见、生产不可见，或反之 | 每张新表/新列同时改 `models.py` + 迁移；增加"空库 upgrade head"与"含 3.3.1 历史数据 upgrade"测试 |
| R2 | 探针包 `FILES` 白名单是显式列表 | 共享库/parser 未进包 → 远端 ImportError，且**失败发生在客户现场** | 同步改 `build_packages.py` + `install.sh` + manifest 校验；构建后实机校验包内容 |
| R3 | Docker build context = `./backend` | 共享库不在镜像内 → 镜像构建或运行期 import 失败 | 改为根 context，或把 `shared` 复制进 `backend/`（二选一并记录） |
| R4 | 探针 requirements 缺 `regex` | `scan_managed` 风格超时不可用，退化为 `re` 无超时 → 恶意正则可挂住探测线程 | 显式加入 `regex`，并对每条规则限时 |
| R5 | `evidence` 内含原文样本（`data_engine/engine.py:57`） | 违反"报告不含原值" | 阶段 1 收敛：新链路默认不携带样本值；旧链路仅保留向后兼容的**计数** |
| R6 | `Predict`/版本门控靠字符串（`extensions.py:250`） | 旧探针被误判为支持 v2 能力，或 v2 任务被静默降级 | 改为 capabilities 协商；缺失 capabilities 时按 legacy 能力集处理，明确报错而不是假装成功 |
| R7 | 单 pending 文件（`inventory.pending.json`/`data-assets.pending.json`） | 一次只能排队一个报告，无法承载进度/多次重试 | 扩展为有界队列时**必须**兼容迁移旧文件、原子写入、容量上限，并测 ACK 丢失 |
| R8 | `Task` 无版本快照字段 | 热更新后无法解释"这份报告用的是哪版规则" | 报告与任务都增加 ruleset/engine/profile 版本；`Report` 不得无标记混版 |
| R9 | 系统状态语义混用（`probe.status` 用 `degraded`/`online`/`offline`） | 新增 `STALE/DISAPPEARED` 时易与探针状态混淆 | 实例生命周期用独立字段，保留旧 API 小写适配 |
| R10 | 分类分级维度混淆（`DataAsset.sensitivity` 已是 Critical/High/Medium/Low） | 直接用 L1~L4 覆盖旧字段会破坏旧页面 | L1~L4 作为**独立字段**并集中可配置映射，不覆盖旧 `sensitivity` |
| R11 | 测试读取生产 `.env`（本次已修复） | 20 个测试因 `APP_ENV=production` + 真实 bootstrap token 假失败，掩盖真实回归 | `backend/tests/conftest.py` 固定 `APP_ENV=development`、清空 bootstrap token、隔离 `INTEGRATION_DIR/OFFLINE_DIR` |
| R12 | 探针 systemd 沙箱（`ProtectSystem=strict`、`ProtectHome=true`） | 规则缓存/Profile 状态目录若不在 `ReadWritePaths` 内将无法写入 | 规则状态目录放在 spool 下或显式加入 `ReadWritePaths`；`dstprobe` 读不到的目录如实显示覆盖缺口，不为扫 `/root` 改成 root |
| R13 | 未提交的 DLP 改动 | 被误当作本次改动或被覆盖 | 阶段记录区分基线修改与本次修改；不做 reset |

---

## 11. 阶段间合同（Schema / 状态 / 映射 / 指标 / Scope）

### 11.1 Schema 与版本字段

- 共享库与规则包引入 `schema_version`，规则包另带 `ruleset_version`、`engine_version`、`min_agent_version`、`created_at`、`sha256`、`rule_count`、包大小。
- 数据资产报告新增（保持旧字段不变、只增不减）：
  `report_id`、`task_id`、`schema_version`、`scan_id`、`ruleset_version`、`engine_version`、`profile_version`、`budget`、`completed_scope`、`coverage`、`termination_reason`。
- 服务端对旧字段继续按 `scanner`/`complete` 兼容分支处理。

### 11.2 任务状态

- 对外保持 `Pending/Running/Success/Partial/Failed/Cancelled`（`probe_task_service.py:11`）。
- **别名排查已执行**（全库 `status` 字面量扫描）：探针任务链路只使用上述 6 个大写值，小写词只出现在 `current_stage`（`workers/tasks.py:303` 的 `done/partial/failed`）。其它域使用独立词表（部署：`CREATED/WAIT_CALLBACK/ONLINE`；情报：`imported`；告警：`new/open`；集成：`disabled`），**不得混用**。
- 超时优先用附加字段表达：`reason_code=TIMEOUT` / `termination_reason`，保持旧客户端仍能识别 `Failed`。
- 不新增旧页面永远不认识的终态。

### 11.3 分类分级映射

- 维度一：`Critical/High/Medium/Low`（既有风险严重度，`Asset.risk_level`、`DataAsset.sensitivity`、`DetectionFinding.severity`）。
- 维度二：`L1~L4`（本次新增数据分级）。
- 二者通过 `backend/app/services/classification.py` 的**集中、可配置、可解释**映射关联，不互相覆盖；映射不是法定分类标准，UI 需注明。

### 11.4 聚合指标口径（类型中心 P0）

- 敏感类型、分类等级、当前 DataObject 数、ACTIVE AssetInstance 数、主机数、确认副本数、疑似副本数。
- **确认重复副本** = Σ over 各完整 Hash 对象 `max(active_instance_count - 1, 0)`。
- **疑似副本** = 相同 PARTIAL_FINGERPRINT 形成的候选对象/疑似副本，单独统计，不得混入确认副本。
- 无可靠 Hash/指纹时，使用作用域内独立身份，绝不用空 Hash/文件名/大小全局去重。
- 主机身份不得仅凭 IP 合并；无真实关联时 `system_count`/`network_observation_count`/`risk_count` 不得捏造。

### 11.5 Scope 完整性

- Scope = 路径 + 深度 + 文件类型 + 排除条件 + Profile 版本 + 探针身份。
- 只有本次 Scope **确认完整**且终态 `Success` 时，才允许把该 Scope 内未发现的实例标为 `NOT_OBSERVED`。
- `Partial`/`Failed`/`Cancelled`/超时**不得**批量标记未发现。
- 区分"设计范围之外"（不算漏扫）与"执行不完整"（记为 Partial）。`STALE`/`DISAPPEARED` 只预留，不在无时间与证据策略前自动推断物理删除。

---

## 12. 实测基线与隔离测试方案

### 12.1 测试入口与环境（实测）

- 运行方式：`source/.venv/Scripts/python.exe -m pytest backend/tests`（Windows 开发机）；`backend/pyproject.toml` 设 `testpaths=["tests"]`、`pythonpath=["."]`。
- 用例总数：**226**（`--collect-only` 实测；阶段 1 新增 63 个用例后为 **289**）。
- 本次修复测试隔离前：**20 failed**；修复后：**6 failed**，其余通过。

> **阶段 1 更正**：下表原列的 `test_adapter_pipeline::test_adapter_engine_runs_in_pipeline` 并非 tshark 环境问题，而是阶段 0 在 `conftest.py` 中临时加入 `PRESIDIO_ENABLED=false` 造成的；该行已删除，用例恢复通过。阶段 1 端到端实测为 **5 项环境性失败**。

修复后仍失败的 5 项，**全部为环境性失败，已逐条核实与业务逻辑无关**：

| 用例 | 失败原因 |
|---|---|
| `tests/probe/test_probe_identity.py::test_first_registration_persists_identity` | 断言 `stat.S_IMODE == 0o600`，Windows 上 chmod 语义不同（实测 `438`） |
| `tests/test_api.py::test_health` | 断言 `status == "ok"`，本地无 Redis 时返回 `degraded` |
| `tests/engine/test_protocol_engine.py::test_protocol_engine_runs_on_fixture` | 依赖 `tshark`；已核实 `shutil.which("tshark")` 为空（`backend/app/services/protocol_service.py:61`） |
| `tests/test_protocol_service.py::test_stream_tshark_watchdog_timeout` | 依赖伪造的 `tshark` shell 脚本 + PATH/bash |
| `tests/test_protocol_service.py::test_parse_pcap_total_exceeds_index_limit` | 依赖 tshark 统计真实包总数 |

→ 按提示词要求，**Linux 权限、systemd、采样与探针行为必须在 Linux 环境验证**，不得把上述 Windows 失败当成业务缺陷，也不得为了让它们变绿而改断言。

### 12.2 隔离要求（已落实/待落实）

- 已落实：`backend/tests/conftest.py` 在导入任何应用模块前固定
  `APP_ENV=development`、`PROBE_BOOTSTRAP_TOKEN=""`、`DATABASE_URL=sqlite:///./data/test.db`、
  `STORAGE_DIR`/`REPORT_DIR`、`INTEGRATION_DIR`/`OFFLINE_DIR`（指向临时目录）、`ADMIN_PASSWORD=test-admin-password`。
  `PRESIDIO_ENABLED` 保持默认、**未**固定为 `false`：固定它会破坏 `test_adapter_pipeline::test_adapter_engine_runs_in_pipeline`。
- 待落实：PostgreSQL 迁移与并发验证需要独立 Compose 项目与独立库；**SQLite 单测不能替代**。本次将新增：
  - 空库 `alembic upgrade head`；
  - 带 3.3.1 历史数据（含现有 5 条 `DataAsset`、历史 Task）的升级演练；
  - 重复执行 `upgrade head` 幂等；
  - 旧记录与引用不丢失断言。

### 12.3 本轮新增测试计划（按阶段）

- 阶段 1：共享引擎单测（validator/别名/置信度/重复命中合并/正则超时/无 NLP 模型可启动）、报告序列化拒绝嵌套原值、合法字段名不误拒、探针与 NetDLP 确实调用共享代码的断言、现有 DLP 回归。
- 阶段 2：正确/错误 SHA256、畸形 Schema、超大包、恶意正则、版本不兼容、下载中断、缓存损坏、发布时并发扫描、回滚、旧探针心跳、新 API 认证与越权。
- 阶段 3：文件各位置敏感值、编码/行边界/重复区间、JSON 片段降级、XLSX sharedStrings/压缩攻击/超预算、空/损坏/变动文件、符号链接、缓存命中与规则失效、Hash 上限、部分指纹与完整 Hash 区分、取消检查点。
- 阶段 4：双路径同 Hash 聚合、不同主机身份、空 Hash 不聚合、候选副本标签、多报告重复与并发上传、ACK 丢失、旧 pending 文件、改名/排除/深度变化、Partial 不误标消失、终态不被覆盖、旧 3.3.1 任务与认证、PostgreSQL 迁移与权限。
- 阶段 5：前端单测 + 类型检查/构建 + 浏览器关键操作（仅构建通过不足以证明页面可用）。

### 12.4 性能基线采集方法

记录真实环境（本机 Docker + Kali 探针）、扫描规模（文件数/目录数/总字节）、实际读取字节、CPU/RSS、持续时间、心跳间隔、上传积压；与改造前对比。不写"低资源"之类无环境标注的虚构指标。

---

## 13. 未验证事实（明确标记）

以下条目**未在本机实测**，实施阶段必须以实际结果更新本文：

1. Kali 探针（`192.168.191.130`）上 `/etc/data-security-toolbox/probe.toml` 的实际内容、`[data]` 段是否启用、`paths` 配置值。**未读取**（需 SSH，凭据来自用户已授权配置，不写入本文）。
2. Kali 上 `dstprobe` 用户实际可读目录范围、systemd 沙箱生效情况。
3. 现有 5 条 `DataAsset` 记录对应的历史 `data_asset_scan` 任务详情（`observed_at`、`scanned_paths`、是否 `complete`）。
4. 生产 PostgreSQL 的实际 Alembic 版本（仅从容器外部确认 API 为 2.7.0，未直连库执行 `alembic current`）。
5. `probe_packages/probe-3.3.1/{amd64,arm64}` 的 manifest SHA256 与当前 `probe/` 源码是否一致（包是否已过期）。
6. `frontend/src/modules/data-security/DataAsset.vue` 的全部字段依赖（仅确认其存在与路由 `/data-assets`）。
7. `docs/` 下既有文档与本次改造的冲突点（尚未逐篇比对）。
8. arm64 实机验证：本机为 x86_64，**不能**声称 arm64 实机通过。

---

## 14. 阶段 0 结论与下一阶段输入

- 基线成立：平台 2.7.0 / 探针 3.3.1，架构清晰，既有任务/认证/幂等/部署通道可直接复用。
- 阶段 1 的**第一硬约束**是消除三份分叉的正则实现，并把 `evidence` 中的原文样本彻底移除；这两项同时是阶段 3/4 的前置条件。
- 阶段 1 的**第二硬约束**是打通共享库的四条分发路径（探针包 / install.sh / Docker context / 依赖），否则后续所有阶段都无法在真实环境验证。
- 阶段 0 完成后按提示词要求**不再等待确认**，直接进入阶段 1。
