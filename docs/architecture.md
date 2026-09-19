# 架构

当前实现见本文；后续拆分步骤见 [解耦操作指南](解耦操作指南.md)。该指南按批次实施；下面第一批（数据资产边界）
与第二批（分析编排与任务入口）已落地，其他拟新增模块仍按计划描述。

## 数据资产采集与展示边界（2026-09-19 第一批）

`DataAsset.vue -> useDataAssetCollection -> api/probes -> api/data_collection -> probe_task_service`
负责采集任务；`useDataAssetList -> api/dataAssets -> api/data_assets` 负责旧资产列表/详情。
类型/对象/实例页面仍经 `api/data_catalog`，其查询读 `services/data_objects/queries.py`。

上报 `data_collection_schemas -> data_collection -> ingestion -> identity/coverage/evidence/persistence/projection`，
仍由路由持有同一 Session 并 commit；模型、旧投影与任务状态在同一事务保存。
`data_object_service.py` 保留兼容导出。探针鉴权由 `api/dependencies.py` 复用，
任务创建冲突由服务抛领域异常，再由 `api/error_handlers.py` 映射为原 404/409。
具体修改路径见 [数据资产开发入口](数据资产开发入口.md)。

## 分析编排与任务入口边界（2026-09-20 第二批）

`api/* -> services.task_dispatch（按注册名派发）-> Celery 队列 -> workers/*_tasks`
是唯一派发链路：路由与领域服务不再导入 `app.workers`，应用层也不引用 worker 模块。
任务行持久化在 `services/task_service.py`；跨域分析编排在 `application/analysis.py`
（`run_pipeline`、`run_correlations_and_alerts`、`upsert_incident`），只依赖领域逻辑与派发端口，
既不 import `app.api` 也不依赖被装饰的 task 对象。事务边界不变：只有 `run_pipeline` 自建 session 时才 commit。

`domain/evidence_identity.py` 负责 finding 证据里的资产/IOC 身份解析，`incident_engine` 只重导出旧名；
这与 `services/data_objects/identity.py` 的文件身份是两件事，不合并。

worker 任务按职责分为 `workers/{analysis,notification,maintenance}_tasks.py`，生命周期在 `workers/task_runtime.py`，
注册名集中在 `workers/task_names.py`，旧 `workers/tasks.py` 仅兼容重导出。
Celery 任务名、参数顺序与队列路由属于兼容边界，不随文件位置改变。

系统由三部分组成：

1. Probe Agent：单进程、低资源，只负责采集与上传
2. Backend Analysis Platform：FastAPI + Celery + PostgreSQL + Redis，负责分析、调度、存储、报告
3. Vue Management Console：Vue 3 + Element Plus + ECharts，负责统一管理

分析链路：

`Probe 采集 -> 上传文件/资产/PCAP -> Celery 任务 -> 后端分析服务 -> PostgreSQL 存储 -> 前端展示 -> 报告生成`

职责边界：探针只在被监控主机执行采集、PCAP/文件分片上传、心跳、资产盘点和受控命令；不执行服务端风险评分、告警关联或报告生成。FastAPI 服务端负责探针注册鉴权、接收和持久化原始数据、创建任务及提供查询 API；Celery worker 负责调用检测引擎、RiskEngine、IncidentEngine 并回写 DetectionFinding/Alert/Incident；Vue 前端只负责登录、配置、任务状态和结果展示。数据通过 `X-Probe-ID`/`X-Probe-Token` 标识探针，原始数据进入 PostgreSQL/文件存储，任务通过 Redis 投递，分析结果再由 API 返回前端。

组件位置检查：

| 组件 | 执行位置 | 输入 | 输出 |
| --- | --- | --- | --- |
| 探针采集、TCP 盘点、心跳 | 受监控主机 Probe | 本机流量/文件/资产 | 上传任务、资产元数据 |
| FastAPI 接入与鉴权 | backend | 探针 HTTP、前端 HTTP | 数据入库、Celery 任务 |
| tshark/dpkt、Zeek、Suricata、Nuclei | worker（部分工具由 API 镜像提供状态探测） | PCAP/扫描目标/适配器数据 | DetectionResult |
| Sigma、协议、流量、数据、资产、威胁情报引擎 | worker | DetectionContext | DetectionResult |
| RiskEngine、IncidentEngine、告警 | worker | DetectionResult/历史结果 | Finding、Incident、Alert |
| Vue + nginx | frontend | API 返回数据 | 管理界面 |

Zeek/Suricata 通过 `EXTERNAL_ENGINE_DIR` 提供可选外部引擎通道，默认核心解析使用 tshark/dpkt。

V2.1 新增 `Integration Adapter Layer`，统一第三方组件输入：

`第三方工具输出 -> IntegrationAdapter -> DetectionResult -> RiskEngine -> DetectionFinding`

适配器包括 Zeek、Suricata、Presidio、MISP、osquery/Wazuh、OpenSCAP。事件关联由 `incident_engine` 对多个 Finding 按时间、资产、IOC、攻击链聚合为 Incident。

## PCAP 工作台与传输文件

- 手动上传返回 `id/task_id/duplicate`。重复上传直接定位已有记录，新上传跟踪分析任务；
  去重查询先于队列背压检查。前端与上传网关使用独立 30 分钟超时。
- 包列表使用 `/pcaps/{id}/packets` 的分页及 `search` 参数，计数区分捕获总数与索引数；
  TShark 索引包含 IPv6 与非 IP 帧地址。包详情读取截止目标帧的原始字节和协议树。
- `services/pcap_files.py` 在 worker 中独立于 DLP 告警提取文件：复用 HTTP 重组与 MIME
  解析，并调用 TShark HTTP/FTP-DATA/SMB/TFTP/IMF 原生对象导出。普通文件也会保留。
- 文件保存到 `STORAGE_DIR/pcap_objects/{pcap_id}/{sha256}`，清单与提取覆盖状态写入
  `AnalysisResult(module='pcap_files')`。文件名只作显示，原始传输内容不作为路径。
- `/pcaps/{id}/files` 返回最新提取清单；`/files/{sha256}` 返回分页文本/Hex 预览，
  `/files/{sha256}/download` 返回附件。两者均须满足管理员认证、抓包归属与清单关联。
- 每次最多处理 200,000 帧、保留 500 对象 / 128 MiB（单文件 32 MiB），原生导出限时
  120 秒；HTTP 重组沿用既有 2 MiB/流、32 MiB 总预算。达到限制或缺包明确显示不完整。
  二进制文本视图是字节解码，Hex 保留原始值；不进行 TLS 解密。
- 旧抓包无提取清单时显示需重新分析；不根据第三方事件中的任意路径下载文件。

## 规则加载与告警追溯

- `rules/catalog.py` 声明 15 个引擎的规则来源；`library.py` 统一枚举随包文件和运行期规则，
  `code_catalog.py` 将实际代码检查和共享敏感检测定义加入清单。清单计数是资源数，不是签名数。
- 在线同步先下载到隔离暂存目录，校验体积、路径、格式和兼容性，再原子切换 `active.json`
  指向的新版本；失败保留原版本。Suricata 使用原生命令校验，Sigma 仅接入支持的条件子集。
- Sigma 逐事件匹配字段和条件，上游 logsource 需要输入事件的 `_logsource` 或上下文对应信息；
  不把不同事件拼接成一次命中，不猜测日志来源。
- Wazuh、osquery、OpenSCAP 等外部资源与已接入检查分别标识；下载不等于目标主机已执行。
  Zeek 上游策略作为参考资源，本机执行已接入的站点脚本，不自动执行整库脚本。
- 引擎结果保存命中规则快照和 SHA256，告警优先展示快照。旧告警无快照时，明确展示当前定义，
  不冒充历史版本。规则列表采用元数据查询，原文通过受清单限制的 `/rules/content` 按需读取。
- Suricata 在临时工作目录将 Linux cooked-v2 抓包转换为兼容头格式，保留原始载荷和时间戳，
  不修改源 PCAP；Zeek/Suricata 原生命令失败向上报告，不再吞成空结果。

## 统一检测引擎

所有检测器实现 `DetectionEngine.analyze(context) -> list[DetectionResult]`，通过 `EngineRegistry` 注册，由 `DetectionPipeline` 统一调度。

检测结果统一包含：`engine`、`rule_id`、`severity`、`confidence`、`evidence`、`recommendation`、`timestamp`、`risk_score`、`risk_level`。

风险评分公式：

`base = severity_weight * 20`

`risk_score = min(100, base * exposure_factor * data_sensitivity * threat_factor * confidence)`

## 模块关系

| 模块 | 依赖 | 边界 |
| --- | --- | --- |
| `app/api/*` | `app/services/*`、`app/models.py`、`app/core/*` | 只做鉴权、参数校验、查询编排，不做检测计算 |
| `app/api/v1.py` | `app/api/data_assets.py`、`app/api/pcaps.py` 等域模块 | 只聚合子路由（`include_router`），不重复声明路径 |
| 域路由（`data_assets.py`、`data_collection.py`、`pcaps.py`…） | 共享 `app/api/dependencies.py`、`app/api/*_presenter.py` | 每个域只声明自己的路径与响应结构；共享鉴权/守卫与序列化下沉到依赖与 presenter |
| `app/workers/tasks.py` | `app/engine`（pipeline）、`app/incident_engine`、`app/services/*`、`app/integrations/*` | 任务入口，负责事务与回写 |
| `app/engine/*` | `app/engine/core/*` | 每个引擎实现 `analyze(context) -> list[DetectionResult]` |
| `app/incident_engine` | 仅依赖 `DetectionResult` | 对外暴露 `evidence_asset_keys()` / `evidence_ioc_keys()` 供他人复用 |
| `app/services/*` | `app/models.py` + 外部工具（tshark、nuclei…） | 领域逻辑，不直接处理 HTTP |
| `frontend/src/modules/*` | `frontend/src/api/*` → `/api/v1` | 只消费 API，不承载业务判定 |

约束：各检测引擎由 `EngineRegistry` 注册、`DetectionPipeline` 调度，彼此不直接 import；
横向共享数据统一通过 `DetectionContext.data` 传递（如 `dlp_policy`、`iocs`、`cve_lookup_enabled`、`probe_id`）。
凡是需要从 evidence 解析「这是哪台主机 / 哪个指标」的模块，必须复用 `app.incident_engine.engine`
的 `evidence_asset_keys()` 与 `evidence_ioc_keys()`，避免同一份 evidence 在不同模块被解读成不同资产。
路由按业务域拆分：聚合入口只 include 一次子路由，`/api/v1` 前缀只叠加一次；
跨域复用的鉴权与上传守卫放 `app/api/dependencies.py`，跨域复用的响应结构放 `app/api/*_presenter.py`，
不新建会继续膨胀的通用 `utils.py`。

## 数据流

1. 探针按 `segment_seconds` 切片抓包，落到本地 spool，按 `X-Probe-ID`/`X-Probe-Token` 上传 `pcaps`。
2. 上传同时提交资产盘点结果（`assets`）、数据资产清单（`data_assets`/`data_objects`/`asset_instances`）、文件哈希（`files`）。
3. FastAPI 落库并创建 `tasks` 记录，任务经 Redis 投递给 Celery worker。
4. worker 组装 `DetectionContext`（flows、packets、log_lines、assets、data…），跑 `DetectionPipeline`。
5. 每个 `DetectionResult` 落 `detection_findings`；`RiskEngine` 计算 `risk_score`/`risk_level`；
   `IncidentEngine` 按「时间窗口 + 资产 + IOC」聚合成 `incidents`；命中的告警落 `alerts` 并按需投递 `alert_deliveries`。
6. 前端通过 `/api/v1` 查询，报告由 `reports` 模板渲染。

## 服务关系

| 服务 | 作用 | 依赖 |
| --- | --- | --- |
| `postgres` | 唯一持久化存储 | — |
| `redis` | Celery broker + 结果后端 | — |
| `backend` | FastAPI 接入、查询、鉴权、上传落盘 | postgres、redis |
| `worker` | 通用分析任务（检测、情报同步、告警投递） | postgres、redis |
| `beat` | 定时任务：探针任务超时、PCAP 保留清理、worker 能力心跳、Wazuh 告警同步、下发超时清扫 | redis |
| `deployment-worker` | 独占探针下发/回收（SSH 通道） | postgres、redis |
| `frontend` | nginx 托管 Vue 构建产物并把 `/api` 反代到 backend | backend |
| `flower` | Celery 监控 | redis |

## 核心类 / 组件

| 组件 | 位置 | 职责 |
| --- | --- | --- |
| `DetectionContext` | `app/engine/core/context.py` | 一次分析的全部输入（数据 + 共享上下文） |
| `DetectionEngine` / `EngineRegistry` / `DetectionPipeline` | `app/engine/core/` | 引擎接口、注册表、调度 |
| `DetectionResult` | `app/engine/core/result.py` | 统一检测结果（engine/rule_id/severity/confidence/evidence/…） |
| `RiskEngine` | `app/engine/risk_engine/` | 风险评分与分级 |
| `IncidentEngine` | `app/incident_engine/engine.py` | 事件聚合；`evidence_asset_keys()` / `evidence_ioc_keys()` |
| `ThreatIntelEngine` | `app/threat_intel/engine.py` | IOC 命中（`TI_IOC_001`）、本地 CVE 关联（`CVE_*`） |
| `ProtocolService` | `app/services/protocol_service.py` | PCAP 解析、协议分类（`protocol_layer()`） |
| 下发/回收状态机 | `app/deployment/{record,removal}.py` | 探针部署与卸载的事件流水与幂等 |

## 数据库关系

```
probes 1---n assets            probes 1---n pcaps 1---n flows / packets
probes 1---n files             probes 1---n probe_deployments 1---n probe_deployment_events
probes 1---n asset_instances   probe_deployments 1---1 probe_deployment_credentials
data_objects 1---n asset_instances        rule_sets 1---n rule_set_versions / rules
tasks 1---n detection_findings            detection_findings 1---n alerts 1---n alert_deliveries
incidents（自持 findings JSON 与 fingerprint 去重，按 evidence.asset / evidence.assets 归属资产）
scan_profiles 驱动探针侧扫描；reports / audit_logs / system_settings / integration_status 为平台侧记录
```

说明：`assets` 是「主机 + 服务」粒度（同一 IP 的不同端口/服务各一条，`asset_type='service'`）；
`data_objects` / `asset_instances` 是探针采集到的数据对象及其在具体探针上的物理副本，身份为
`(probe_id, 规范化绝对路径)`。

## API 调用关系

- 控制台：`frontend/src/api/*` → nginx `/api` 反代 → FastAPI `/api/v1/*` → `app/services/*` → `app/models.py`。
- 探针：`probe/probe.py` → `/api/v1/probes/register`、`/probes/{id}/heartbeat`、`/volumes/*`、`/pcaps/*`、
  `/assets/*`、`/files/upload`、`/rulesets/*`，全部带 `X-Probe-ID` + `X-Probe-Token`。
- 任务链：API 建 `tasks` → Redis → worker 执行 → `detection_findings` / `incidents` / `alerts` → 前端轮询查询。
- 维护端点：`/api/v1/admin/*`（如 `data-assets/backfill`、`data-assets/rebuild-projection`），写审计后返回统计。

## 探针与服务端通信关系

| 方向 | 触发 | 通道 | 说明 |
| --- | --- | --- | --- |
| 探针 → 服务端 | 首次安装 | HTTPS + `bootstrap_token` | `/probes/register` 换取 `probe.id` 与 `probe.token`，持久化到 `/etc/data-security-toolbox/probe.token` |
| 探针 → 服务端 | 每 30s | HTTPS + 双头鉴权 | `/heartbeat` 上报存活、版本、采集状态 |
| 探针 → 服务端 | 每 `segment_seconds` | HTTPS 分片上传 | PCAP 段、资产盘点、数据资产、文件哈希 |
| 探针 → 服务端 | 每 `ruleset.poll_seconds`(900s) | HTTPS 下载 + SHA256 校验 | 规则包先校验再原子替换，失败保留旧版本；首启走随包基线快照 |
| 探针 ← 服务端 | 平台触发 | 探针侧轮询 `allow_remote` | 远程扫描 / 数据资产采集任务 |
| 服务端 → 探针 | 管理员下发或回收 | SSH（`deployment-worker`） | 推送安装/卸载脚本；卸载删除白名单固定，成功后才删平台记录 |

安全边界：探针只出站、只读采集，不解密 TLS、不做串接阻断；服务端不反向登录被检主机（除显式的探针下发/回收通道）。

## 引擎命名与规则归属

引擎存在**三套名字**，历史上没有统一，是「按引擎过滤查不到数据」的根因：

| 名字 | 用途 | 例子 |
| --- | --- | --- |
| 控制台路由段（slug） | 前端 URL `/engines/<slug>` | `sigma`、`traffic`、`ioc` |
| 注册表引擎名 | `getEngineRegistry()` / 检测管线 | `sigma_log_engine`、`traffic_engine`、`threat_intel` |
| 落库引擎名 | `detection_findings.engine`（告警 `source` 同源） | 与注册表引擎名一致 |

统一方式：`app/api/v1.py` 的 `ENGINE_PRESENTATION` 定义 slug ↔ 引擎名 ↔ 中文标签，
由 `GET /engine/registry` 下发 `slug` / `label` / `detection_engine` / `rule_count` / `detection_count`，
**前端不再持有任何引擎名单**。

规则库是「引擎 ↔ 规则文件」的唯一枚举点：

```
app/rules/logs/*.yaml|*.yml      -> sigma_log_engine
app/rules/network/*.yaml         -> traffic_engine     (经 interpret_rules 解释执行)
app/rules/compliance/*.yaml      -> compliance_engine  (经 interpret_rules 解释执行)
app/rules/data/*.yar             -> data_engine        (YARA)
$INTEGRATION_DIR/yara_rules/*.yar-> data_engine        (YARA，离线导入)
app/integrations/suricata/rules/*.rules  -> suricata   (随包规则，run_suricata 加载)
$INTEGRATION_DIR/suricata_rules/*.rules  -> suricata   (离线规则包)
```

- `_rule_file_entries()` 枚举上表，`GET /rules` 每项带 `engine`，并支持 `?engine=` 过滤。
- `interpret_rules(context, rule_dir, engine)` 的 `engine` **必须由调用方（引擎自身）传入**；
  写死引擎名会让检测结果落到一个注册表里不存在的名字下。
- 不变式：`/engine/registry` 的 `rule_count` == `/rules?engine=<name>` 的条数（已由
  `tests/test_api.py::test_rule_library_tags_every_file_with_its_engine` 锁定）。
- 注意 `_worker_capability()` 上报的 suricata `rule_count` 单位是 `sid:` 条数（运行时口径），
  与注册表的「规则文件数」不同但都真实。
