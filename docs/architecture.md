# 架构

当前实现见本文；后续拆分步骤见 [解耦操作指南](解耦操作指南.md)。该指南按批次实施；下面第一批（数据资产边界）
与第二批（分析编排与任务入口）边界已落地，第三至七批（PCAP 域、文件证据域、平台资产域、事件/情报域、告警域）
为按域拆出的路由模块与共享 presenter（见「域路由模块」一节），其他拟新增模块仍按计划描述。

## 数据资产采集与展示边界（2026-09-19 第一批）

`DataAsset.vue -> useDataAssetCollection -> api/probes -> api/data_collection -> probe_task_service`
负责采集任务；`useDataAssetList -> api/dataAssets -> api/data_assets` 负责旧资产列表/详情。
`PcapWorkbench.vue -> usePcapWorkbench -> api/pcaps`：工作台只渲染，抓包列表与上传、分析轮询、
包分页与详情、文件预览、TCP 流跟踪的状态与竞态防护都在 composable 里。
`DataAssetJobs.vue -> useDataAssetJobs -> api/tasks|api/probes|api/scanProfiles`：采集任务页只渲染，
任务列表按 `kind=data_asset_scan` 查询，派发/取消/移除与 5 秒自动刷新（卸载即停）都在 composable 里。
`DataTypeCenter.vue -> useDataTypeCenter -> api/dataCatalog`：类型页只渲染，类型行、分级目录与
服务端去重 totals 都在 composable 里；`DataTypeDetail.vue -> useDataTypeDetail`（路由 category + 分页）
同理，翻页走 `setPage()`。
`DataObjectDetail.vue -> useDataObjectDetail -> api/dataCatalog`（对象 + 检测分页 + 证据抽屉）与
`AssetInstanceDetail.vue -> useAssetInstanceDetail`（实例 + 历史开关 + 证据抽屉）同样只渲染，
路由 id 与分页都经 composable 的参数与 `setDetectionPage()`；时间格式化留在视图。
`ScanProfiles.vue -> useScanProfiles -> api/scanProfiles|api/probes`（配置行 + 草稿 + 下发弹窗）与
`RuleVersions.vue -> useRuleVersions -> api/ruleSets|api/probes`（规则集 + 版本 + 探针已观测版本）
同样只渲染：扫描配置翻页走 `setPage()`，探针版本分类（已同步/待更新/同步失败）在 composable 里。
`FileAnalysis.vue -> useFileAnalysis -> api/client`（文件行 + 筛选 + 详情抽屉 + 4 秒刷新）、
`NetworkDlp.vue -> useNetworkDlp -> api/client`（策略表单 + 传输记录 + 正则规则 + 证据竞态守卫）与
`SensitiveDiscovery.vue -> useSensitiveDiscovery -> api/dataAssets`（服务端发现统计 + 图表投影）
同样只渲染。
`IncidentCenter.vue -> useIncidentCenter -> api/incidents`（事件行 + 详情 + 状态流转 + 手工关联）与
`AlertCenter.vue -> useAlertCenter -> api/alerts`（告警行 + 汇总 + 详情 + 状态流转）同样只渲染，
两个页面都只保留筛选字段配置与攻击阶段标签这类静态展示。
`AssetCenter.vue -> useAssetCenter -> api/assets`（资产行 + 详情抽屉 + 关系图投影）与
`api/probes`/`api/scan`（探针下拉与网络扫描控制台）同样只渲染，页面只保留筛选字段配置与
格式化函数这类静态展示。
`DetectionCenter.vue -> useDetectionCenter -> api/detections`（发现行 + 详情抽屉）与 `api/engine`
（引擎下拉、手动流水线）同样只渲染，页面只保留筛选字段配置与格式化函数这类静态展示。
`EngineDetail.vue -> useEngineDetail(name) -> api/engine`（注册表解析）加上 `api/integrations`、
`api/health`、`api/tasks`、`api/rules` 与 `api/detections` 同样只渲染；视图保留路由、导航与
`executionLabels` 这类静态标签。
`Dashboard.vue -> useDashboard -> api/dashboard`（汇总、两条趋势、四组图表序列与两张表）加上
`api/risk`、`api/health` 同样只渲染；视图保留路由与格式化函数，`levelBreakdown` 让两处环形图
共用同一套四级刻度与配色。
`SecurityAudit.vue -> useSecurityAudit -> api/audit`（审计汇总只读 + 粘贴日志分析）同样只渲染；
视图保留 `riskLabels` 这类静态标签与格式化函数，`matchGroups` 由 composable 提供。
`LiveTraffic.vue -> useLiveTraffic -> api/network`（实时窗口）加上 `api/health`、`api/probes`、
`api/pcaps` 与 `api/alerts`（汇总 + 告警流）同样只渲染；告警流的 `EventSource` 归 composable 所有，
卸载时关闭，视图保留路由与格式化函数。
`AlgorithmEvaluation.vue -> useAlgorithmEvaluation -> api/probes`（探针列表）与 `api/crypto`（单个
探针的密码画像）同样只渲染；密码评估与复杂度分析都在浏览器本地计算，视图保留三个展示组件与静态
语言下拉，等级到颜色的映射由 composable 提供。
`RulesCenter.vue -> useRulesCenter -> api/rules|api/engine`（规则库 + 引擎注册表）、
`CveCenter.vue -> useCveCenter -> api/offline|api/client`（本地 CVE + Grype 库与导入任务）与
`IocCenter.vue -> useIocCenter -> api/intelligence|api/client`（指标 + 关联抽屉 + 启停）同样只渲染；
Grype 任务的 2s 轮询由 composable 持有并在卸载时清除，视图保留执行状态标签、CVSS 等级映射、筛选
字段配置与格式化函数。
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

## 域路由模块（2026-09-20 第三批至第十四批）

`api/pcaps.py`（18 条路径）、`api/files.py`（5 条路径）、`api/assets.py`（4 条路径）、
`api/incidents.py`（7 条路径）、`api/alerts.py`（5 条路径）、`api/tasks.py`（5 条路径）与
`api/reports.py`（5 条路径）、`api/detections.py`（3 条路径）、`api/engines.py`（2 条路径）与
`api/dashboard.py`（13 条路径）、`api/probes.py`（9 条路径）、`api/integrations.py`（11 条路径）、
`api/rules.py`（5 条路径）、`api/auth.py`（3 条路径）、`api/health.py`（1 条路径）、
`api/network_scan.py`（2 条路径）、`api/test_data.py`（3 条路径）
分别承载 PCAP 抓包域、文件证据域、平台资产域、事件/情报域、告警域、任务队列域、审计/报表域、
检测/引擎域、看板/流量视图域、探针域、集成/离线导入域、规则域、控制台会话域、平台健康、
主动扫描与手动测试数据，
都由 `v1.router` 只 include 一次、`/api/v1` 前缀只叠加一次，
路径/方法/鉴权/分页与拆分前逐一对应，`v1.py` 自身不再声明任何路径（只做聚合与兼容重导出）。
子路由在 `v1.router` 末尾追加，只改变注册顺序，不改变匹配结果
（全应用没有单段通配路径，路径集合与拆分前一致）。
跨域复用的上传归属（`api/dependencies.py`）、Task 行序列化（`api/task_presenter.py`）、检测结果序列化
（`api/finding_presenter.py`）、事件/IOC 行序列化（`api/incident_presenter.py`、`api/ioc_presenter.py`）
与探针行序列化/规则解析（`api/probe_presenter.py`、`api/rule_presenter.py`）、
队列派发端口（`api/dependencies.py::dispatch_task`，按注册名派发、broker 不可用才回退本进程）
与 worker 能力/规则清单读取（`api/runtime_status.py`，`/health` 与集成目录共用）
只保留一份实现，序列化器共用的时间归一化在 `core/datetimes.py::aware`，列表时间过滤在
`api/query_filters.py`；解析、提取、哈希、告警抑制投递、任务创建/过期（`services/task_service.py`、
`services/probe_task_service.py`）、审计/报表生成（`services/audit_service.py`、`services/report_service.py`）
与检测判定（`app/engine/*`）以及资产关联判定仍在 `services/*`、`incident_engine`，
域路由只做鉴权、分页与响应结构。各域路径/方法由
`tests/test_{pcap,file,asset,incident_ioc,alert,tasks_reports,detection_engine,dashboard,probe,integration_offline,rule,auth,health,network_scan,test_data}_boundaries.py` 冻结，
全应用不允许重复「方法 + 路径」。

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
| `app/api/v1.py` | `app/api/data_assets.py`、`app/api/pcaps.py`、`app/api/files.py`、`app/api/assets.py`、`app/api/incidents.py`、`app/api/alerts.py`、`app/api/tasks.py`、`app/api/reports.py`、`app/api/detections.py`、`app/api/engines.py`、`app/api/dashboard.py`、`app/api/probes.py`、`app/api/integrations.py`、`app/api/rules.py`、`app/api/auth.py`、`app/api/health.py`、`app/api/network_scan.py`、`app/api/test_data.py` 等域模块 | 只聚合子路由（`include_router`），自身不声明路径 |
| 域路由（`data_assets.py`、`data_collection.py`、`pcaps.py`、`files.py`、`assets.py`、`incidents.py`、`alerts.py`、`tasks.py`、`reports.py`、`detections.py`、`engines.py`、`dashboard.py`、`probes.py`、`integrations.py`、`rules.py`、`auth.py`、`health.py`、`network_scan.py`、`test_data.py`…） | 共享 `app/api/dependencies.py`、`app/api/*_presenter.py`、`app/api/query_filters.py`、`app/api/runtime_status.py` | 每个域只声明自己的路径与响应结构；共享鉴权/守卫、序列化、列表过滤与运行时状态读取下沉到依赖、presenter、query_filters 与 runtime_status |
| `app/workers/tasks.py` | `app/engine`（pipeline）、`app/incident_engine`、`app/services/*`、`app/integrations/*` | 任务入口，负责事务与回写 |
| `app/engine/*` | `app/engine/core/*` | 每个引擎实现 `analyze(context) -> list[DetectionResult]` |
| `app/incident_engine` | 仅依赖 `DetectionResult` | 对外暴露 `evidence_asset_keys()` / `evidence_ioc_keys()` 供他人复用 |
| `app/services/*` | `app/models.py` + 外部工具（tshark、nuclei…） | 领域逻辑，不直接处理 HTTP |
| `frontend/src/modules/*` | `frontend/src/api/*` → `/api/v1` | 只消费 API，不承载业务判定 |

约束：各检测引擎由 `EngineRegistry` 注册、`DetectionPipeline` 调度，彼此不直接 import；
横向共享数据统一通过 `DetectionContext.data` 传递（如 `dlp_policy`、`iocs`、`cve_lookup_enabled`、`probe_id`）。
凡是需要从 evidence 解析「这是哪台主机 / 哪个指标」的模块，必须复用 `app.incident_engine.engine`
的 `evidence_asset_keys()` 与 `evidence_ioc_keys()`，避免同一份 evidence 在不同模块被解读成不同资产。
路由按业务域拆分：聚合入口只 include 一次子路由、自身不声明路径，`/api/v1` 前缀只叠加一次；
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
database_connections 1---n tasks(kind=database_scan)；采集结果落在 data_objects / asset_instances(source_kind='database')
```

说明：`assets` 是「主机 + 服务」粒度（同一 IP 的不同端口/服务各一条，`asset_type='service'`）；
`data_objects` / `asset_instances` 是采集到的数据对象及其物理副本，身份为 `(owner_key, 路径)`：
`owner_key` 为 `probe:<探针 id>`（文件）或 `db:<连接 id>`（目标数据库表），`source_kind` 记录来源是
`file` 还是 `database`。数据库表与文件路径因此不会互相顶掉，`probe_id` 对数据库来源为空。
类型中心（`/api/v1/data-types*`）与对象详情的 `host_count` 由此按**观测来源**去重：
`owner_key`（`probe:<id>` / `db:<id>`）算一个来源，不能再直接数 `probe_id`——数据库来源的 NULL 既会
计数崩溃，也会把所有目标库并成一个「空主机」。SQLite 测试库与 0016 之前的旧行 `owner_key` 为空串，
此时用 `probe:<probe_id>` 回退（`app/services/data_objects/queries.py::owner_key_of`）。

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

探针自带运行时（3.7.0 起）：`runtime.tar.gz` 内含私有 CPython 3.11、Python 依赖、`dumpcap`/`tcpdump` 与
库闭包，`probe/runtime_check.py` 用它自检（架构、解释器版本、依赖、抓包、可选平台连通性）。平台下发/回收
前的预检走 `app/deployment/{preflight,runtime}.py`：把同一个运行时上传到目标机临时目录、比对 sha256 后
执行自检，因此目标机不再需要主机 Python 或系统抓包工具，安装也不执行 pip/apt/venv（`probe/install.sh`
先验证再原子替换 `/opt/data-security-toolbox/runtime`）。探针仍以 `dstprobe` + `CAP_NET_RAW`/
`CAP_NET_ADMIN`/`CAP_DAC_READ_SEARCH` 运行，读不到的目录按覆盖缺口上报，不提权重试。

启动链路同样不依赖目标机环境：`ExecStart` 固定为 `probe/run-probe.sh`，它只用 shell 内建命令定位自身目录
（不调用 `dirname`），自设 `PATH` 并导出 `PYTHONUTF8=1`/`PYTHONIOENCODING=utf-8`（systemd 启动时 `LANG` 通常未
设置，否则 CPython 会退回 C 语言环境并按 ASCII 处理 stdio，中文日志直接报错）；`probe/runtime_check.py`
除架构、依赖与抓包工具外，还校验运行时布局完整，并断言解释器来自包内 `python/`（`sys.base_prefix`），
避免主机解释器被顶替进来。

安全边界：探针只出站、只读采集，不解密 TLS、不做串接阻断；服务端不反向登录被检主机（除显式的探针下发/回收通道）。

## 引擎命名与规则归属

引擎存在**三套名字**，历史上没有统一，是「按引擎过滤查不到数据」的根因：

| 名字 | 用途 | 例子 |
| --- | --- | --- |
| 控制台路由段（slug） | 前端 URL `/engines/<slug>` | `sigma`、`traffic`、`ioc` |
| 注册表引擎名 | `getEngineRegistry()` / 检测管线 | `sigma_log_engine`、`traffic_engine`、`threat_intel` |
| 落库引擎名 | `detection_findings.engine`（告警 `source` 同源） | 与注册表引擎名一致 |

统一方式：`app/api/engines.py` 的 `ENGINE_PRESENTATION` 定义 slug ↔ 引擎名 ↔ 中文标签，
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


## 2026-09-20 整改边界（止增与诊断已部署）

原始 PCAP context.path 仍参与检测，但 DataEngine 不再将该容器登记为文档资产；
context.files 中的独立文件继续按文档处理。判定使用上下文来源而非扩展名黑名单。
文档 scan_status/scan_reason 由 application/analysis.py 保存到 DataAsset.extra。
采集终态展示复用 services/data_objects/progress.collection_outcome；新上报写准确阶段，旧任务仅呈现兼容，不修改历史事实。

### 采集预算的两个维度

`shared/scanning/budget.py` 把「遍历是否走完」与「文件内容是否读完」分开记账，两者都要完整才是 `complete`：

- `enumeration_complete`：只有文件/目录/字节/超时/取消/资源/未配置/不可读这类**枚举级**原因会置否。
  它决定探针是否继续遍历，也是「哪些路径压根没被看过」的唯一依据。
- `content_complete`：`row_budget`（累计行数超过 `max_sample_rows × 64`）与 `single_file_limit`
  只属于这一维度。它们仍让整份报告不完整（`complete_scope=false`，因此不会退役未观测实例），
  但不再终止遍历——此前 `/var/backups/dpkg.status.0` 一个文件就把整个 `/var` 的盘点截断成 9 个资产。
- `termination_reason` 优先报枚举级原因，`termination_detail` 与之一致；`collection_outcome`
  仅在 `enumeration_complete=true` 且原因属于内容维度时才改用「部分文件内容达到读取行数上限」措辞。

后端/worker/前端运行镜像已按上述实现重建（2026-09-20）；**探针分发包与在线探针尚未更新**，
因此目录诊断与截断语义的线上生效仍待出包与升级；数据库直连架构仍待实现。

## 2026-09-20 契约变更：命中原文回传

用户明确要求「发现敏感内容之后要回传原文」，因此**本节取代此前「检测证据从不保存/展示匹配到的原始值」
的描述**。变更是有界、集中的，其余脱敏保证不变：

```
探针 shared/sensitive_detection/engine.py
  DetectionHit.matches[:3]  ->  {value: ≤120 字符, context: 该值所在行 ≤240 字符}
        │  （只命中字段名/关键字的命中 matches=[]，表示"没有可回传的原文"）
        ▼
探针 report_guard.raw_text_keys({"matches"})
        │  matches 子树内不脱敏/不截断；Evidence 与 ScanReport 仍不含任何值
        ▼
探针 data_assets._hit_summary -> report.assets[].evidence.hits[].matches
        ▼
平台 services/data_objects/evidence._returned_matches()
        │  以同样上限重裁并做形状校验（只接受非空 value），写入 DetectionEvidence.extra['matches']
        ▼
平台 /api/v1/detections/{id}/evidence -> items[].matches + matches_returned
        ▼
前端 实例详情 / 对象详情「检测证据」抽屉：展开行显示 value + context；
      无 matches 时显示「这条证据没有回传原文（旧版探针，或只命中了字段名/关键字）」
```

- 上限常量：探针 `MAX_RETURNED_MATCHES=3`、`MAX_RETURNED_CHARS=120`、`MAX_CONTEXT_CHARS=240`；
  平台 `MAX_RETURNED_MATCHES/MAX_MATCH_CHARS/MAX_CONTEXT_CHARS` 同值，只收紧不放大。
- 存储：`DetectionEvidence` 仍无存值列，原文位于 `extra['matches']`；合并规则保留最新一组非空原文，
  空列表不会覆盖已有原文。该批没有新增迁移；随后的 P2 批次新增 `0016_database_connections`（当前 head）。
- 边界：`Evidence` / `ScanReport` / 其他任何模型字段都不得出现值；`report_guard.sanitize_report`
  在 `matches` 之外仍按原样脱敏。旧报告没有该字段，读取端按空列表处理。

## 2026-09-20 P2：平台直连目标数据库盘点

目标数据库由**平台自己**连接（不经探针、不经 SSH 隧道），因此连通性测试与采集走同一执行网络
（当前是 worker 容器所在网络）。这条链路复用文件路径上的同一份敏感引擎与同一套证据写入口。

```
前端 DatabaseConnections.vue
  -> useDatabaseConnections.ts -> api/databaseConnections.ts
  -> /api/v1/database-connections（CRUD / test / schemas / tables / scans / scans/{task_id}）
        │  api/database_connections.py：管理员会话 + 审计；响应只含 password_set
        ▼
  services/database_scan/connection_service.py
        │  字段校验、口令 AES-GCM 加密（AAD = db:<连接 id>:<用户名>:<密钥 id>）、
        │  任务配置快照 + config_hash、单连接同时只允许一个采集任务
        ▼
  tasks(kind=database_scan) --Redis--> workers/analysis_tasks.database_scan_task
        ▼
  services/database_scan/scan.py
        │  adapters.open_read_only：每连接执行 SET SESSION TRANSACTION READ ONLY 并回读校验
        │  枚举库/表 → sample_table(SELECT * LIMIT) → detect.scan_table（共享敏感引擎，按列）
        │  → ingest：DataObject(database_table) + AssetInstance(source_kind='database') + 证据
        │  → retire_unseen（只在范围完整时）→ 汇总（按表明细 / notes / table_errors）
        ▼
  /api/v1/asset-instances?source_kind=database、/api/v1/data-objects/{id}、
  /api/v1/detections/{id}/evidence —— 原文出口与文件来源共用同一个
```

- 只读保证：read-only 在连接池的 connect 钩子里对**每条**连接执行，且回读 `@@session.transaction_read_only`；
  服务器若回答「可写」直接拒绝采集（`read_only_violation`）。标识符只来自反射，模块内没有接收 SQL 文本的入口。
  真机负对照：对目标库执行 `CREATE TABLE` 被 MariaDB 以 `1792 Cannot execute statement in a READ ONLY transaction` 拒绝。
- 引擎白名单：`mysql` → PyMySQL、`postgresql` → psycopg2；驱动选项只允许
  `charset` / `sslmode` / `connect_timeout_seconds` / `statement_timeout_seconds`（秒数夹取 1..3600）。
- 预算与终止：`database_scan_sample_rows`（默认 50 行/表）、`max_tables`、`max_seconds`、`value_chars`、
  `connect_timeout`；`termination_reason` 汇报到底是哪一项截断（complete / table_budget / time_budget /
  read_error / no_tables / cancelled），停止请求只在表之间生效，已读到的结果保留。
- 检测口径：只有**值命中**计入 counts/categories；字段名与关键字线索进 `candidates` / `field_only_categories`，
  不把 `id_card` 这样的列名当成数据；命中原文与文件来源受同一上限约束。
- 凭据形态：口令只写不读，响应只有 `password_set`；快照携带 `password_key_id`，用户名或密钥在任务排队后变更
  则明确报 `CredentialError`，不会静默改用其他凭据读取目标。
- 安全影响（需后续任务承接）：报告、探针本地缓存与 `DetectionEvidence.extra` 现在会保存敏感原文，
  因此探针→平台传输与数据库静态保护的重要性高于改造前（此前载荷可证明不含值）。


### 采集任务与资产成员关系（2026-09-20）
探针报告 → ingestion 返回实际入库 asset_instance_ids → data_collection 写 Task.result；
任务页 → GET /asset-instances?task_id=… → 按任务探针及持久化实例 ID 查询当前资产 → 实例详情。
旧任务仅能按 probe + last_scan_id 恢复仍可关联的实例，响应 association 标明限制，不根据路径/时间猜测历史成员。

## 2026-09-20 共享文件来源（FTP/FTPS/SFTP）盘点

共享目录由**平台自己**连接读取（不经探针、不经 SSH 隧道），因此连通性与采集走同一执行网络（当前是 worker
容器所在网络）。这条链路与数据库直连共用同一份敏感引擎和同一套证据/资产写入口。

```
前端 SourceManagement.vue（来源管理：共享文件 / 数据库 / 主机探针 / 手动文件四个入口）
  -> FileSources.vue + useFileSources.ts -> api/fileSources.ts
  -> /api/v1/file-sources（列表 / 新建 / 更新 / 删除 + {id}/test、{id}/scan）
        │  api/file_sources.py：管理员会话 + 审计（只记协议与任务号）；响应只有 password_set
        ▼
  services/file_scan/service.py
        │  字段校验、口令 AES-GCM 加密（AAD = file-source:<id>:<用户名>:<密钥 id>）、
        │  协议/地址/端口不可改（换端点就新建来源）、共享目录可改、单来源同时只允许一个采集任务
        ▼
  tasks(kind=file_source_scan) --Redis--> workers/analysis_tasks.file_source_scan_task
        │  beat 每 60 秒跑 file_source_schedule，按 next_scan_at 周期派发（也可手动）
        ▼
  services/file_scan/scan.py
        │  adapters.connect：FTP / 显式 FTPS（prot_p）/ SFTP（主机指纹固定）
        │  枚举目录（深度/文件数/字节/时限/取消预算）→ 只读下载到临时文件 → ingest.analyze
        │  （共享 sensitive_detection 引擎）→ ingest.store：DataObject + AssetInstance
        │  （source_kind='file_share'，owner_key='file-source:<id>'）+ 检测证据
        │  临时文件检测后立即删除；未再观测到的路径只在范围完整时标记 NOT_OBSERVED
        ▼
  /api/v1/asset-instances?owner_key=file-source:<id>、/api/v1/data-objects/{id}、
  /api/v1/detections/{id}/evidence —— 原文出口与文件/数据库来源共用同一个；
  删除来源只删除这份配置，已采集资产与证据保留（采集中的来源不可删）
```

- 传输只读：适配层只使用 `MLSD`/`LIST`、`RETR` 与 SFTP 读操作，没有写/删/改接口；远端名字先经
  `child_path` 校验（拒绝 `..`、路径分隔符、CR/LF/NUL），符号链接只记 `skip`、永不跟随。
- 列目录兼容：优先 `MLSD`，服务器回答 500/502（如 vsFTPd 3.0.5，`FEAT` 未声明该命令）时回退解析
  `LIST` 的 ls -l 行；550 等真实回答不重试，直接归类为 `path_error`。失败一律转为类别
  （`auth_error`/`path_error`/`protocol_error`/`timeout`/`dns_error`/`unreachable`），服务器回显文本不落库。
- 预算与终止：`max_files`、`max_depth`、`max_bytes`、`max_file_bytes`、`max_seconds`（各自有上限），
  逐文件如实记录 `coverage` 与 `termination_reason`（`complete`/`row_limit`/`sampled`/`single_file_limit`/
  `file_changed_during_read`/`depth_limit`/`file_budget`/`byte_budget`/`time_budget`/`cancelled`）。
- 身份：`owner_key='file-source:<id>'`、`path=远端绝对路径`；内容哈希只作为“是否变化”的证据
  （`hash_type='scoped'`），不用于跨来源合并。
- 界面：`/source-management`（`SourceManagement.vue`）与 `/asset-inventory`（`AssetInventory.vue`，
  同页可切换敏感发现模式）；菜单只保留这两个入口，旧 URL（`/database-connections`、`/data-assets`、
  `/sensitive`）继续可用。


## 2026-09-20 统一规则源：一条规则，四引擎共享，命中带原文

```
控制台「规则库」（POST /api/v1/dlp/rules 手写规则；presidio 导入/更新）
        │  data/integrations/dlp_rules/*.json（manual-*.json / presidio.json）
        ▼
services/sensitive_engine.analyst_rules()   ← 规则库 → 共享规则格式（EMAIL 套 email_shape 校验器）
        │  analyst_signature()（mtime+size）变化才重建
        ▼
scan_engine() = shared/sensitive_detection 内置包 + 手写规则      scan_all(text, source_type=…)
        ├── DataEngine（engine/data_engine/engine.py：scan_text / infer_columns）
        ├── 文件来源采集（services/file_scan/ingest.py）      → DetectionEvidence.extra['matches']
        ├── 数据库直连盘点（services/database_scan/detect.py）→ DetectionEvidence.extra['matches']
        └── 网络防泄密（services/dlp/detect.py::inspect_content）
                 │  内置包按 policy['categories'] 过滤；手写规则命中不过滤
                 ▼
            DLP 传输对象 matches（value + context）→ finding 证据 → 告警 → SSE security.alerts → /network/live
```

- 控制台规则 → 探针的路径是**两步**：`ruleset_service.sync_analyst_rules()` 先把规则镜像进规则集工作副本
  （已发布版本不可变），操作者发布后才进 probe 下载的规则包。平台侧三条链路无需发布即可生效。
- 命中原文的唯一出口仍是 `matches`：每命中 ≤3 条、`value` ≤120、`context` ≤240，探针与平台两侧各自重裁；
  网络侧由 `shared/sensitive_detection/engine.py::text_matches()` 生成关键词命中的原文。
- `kind` 保留实体原样大小写（自定义 `测试`/`COMPANY` 不再被小写化），只有内置包回落历史小写名；
  类别过滤按大小写不敏感比较，`infer_columns` 为没有历史类别的手写规则补 `counts`。
- 告警与否由风险分决定，不由命中决定：`_capture_exposure()` 只看目的地址是否公网
  （`internal_only` → 2.0，`external_destination` → 3.0），`alert_policy.high_finding_min_risk`（默认 60）
  再拦一道。同一份含 `张三` 的命中，内网互传 `risk=51`（不告警、网络防泄密页可见），外网外发 `risk=76.5`（告警）。

## 网络 DLP 域分层与规则源单一映射（2026-09-20 第三十批）

```
app/api/*（DLP 策略读写、规则清单）        app/engine/dlp_engine.py（DetectionEngine 适配）
        │                                        │
        └──────────► services/dlp/detect.py ◄────┘   检测编排：唯一同时握着抓包与策略的一层
                          │  capture.reassemble / capture.http_objects
                          │  stream_objects（没有 HTTP 解析器的明文协议仍做有界文本扫描）
                          ▼
             services/dlp/{policy,self_traffic,capture}
                          │
             services/dlp/constants.py（上限、内置兜底策略、自身流量标记）
                          │
        services/rule_library.py（规则库：唯一知道 data/integrations/dlp_rules 布局的模块）
                          ▲            │ stored_rule()
                          │            ▼
        sensitive_engine.analyst_rules() ─┬─ ruleset_service.import_working_rules()
                          ▼              └─ 规则集工作副本 → 发布 → 探针规则包
        services/sensitive_engine.py（平台侧唯一规则加载入口，按 mtime+size 签名重建）
```

- 实现分五层：常量 → 策略 / 自身流量判定 / 抓包与 HTTP 解析 → 检测编排。`app/services/dlp_service.py`
  只剩兼容重导出，旧调用方与回归测试继续可用；新代码 import `app.services.dlp`。
- **规则源只有一份映射**：`rule_library.stored_rule()` 把规则库的一条规则转成共享规则/规则包格式，
  平台侧扫描（`sensitive_engine.analyst_rules()`）与下发给探针的工作副本
  （`ruleset_service.import_working_rules()`）共用它。此前工作副本自己再读一遍同一份 JSON，
  导入规则**漏掉了 `email_shape` 校验器**，同一条规则在平台与探针上命中口径不同。
- **规则库布局只有一处**：`rule_library.rule_store_directory()` / `rule_store_files()` 是
  `data/integrations/dlp_rules/*.json` 的唯一读者。引擎刷新签名（`analyst_signature()`）、规则来源清单
  （`api/rule_presenter.py`）与启停写入（`rule_library.set_rule_enabled()`，由 `PATCH /dlp/rules/{id}` 调用）
  都不再各自 glob 该目录。
- **旧环已断**：`rule_library` 曾 `from app.services.dlp_service import masked`，DLP 侧又 import 规则库的
  置信度常量，两个模块互相依赖；`masked()` 现在在中立的 `services/masking.py`。
- 边界由 `backend/tests/test_dlp_boundaries.py`（7 项）锁定：分层文件集合、无 `app.api`/`app.workers`
  依赖、只有检测层引用敏感引擎、规则库不再 import 网络 DLP、兼容外观只做重导出、单一映射，
  以及「导入规则在规则包里带着平台侧同样的校验器」。


## 数据库连接前端状态与视图边界（2026-09-21 第三十一批）

`DatabaseConnections.vue -> useDatabaseConnections` 保留连接列表、选择、删除/连通测试及刷新协调。
协调入口向三个子 composable 显式传入响应式目标与回调，子模块不互相 import：

- `useDatabaseConnectionForm(engines, selectCreated, load)`：拥有响应式编辑草稿与保存状态，创建成功后通知
  协调入口选择新连接，再刷新列表。编辑密码为空不提交 password，保存成功才清空草稿口令。
- `useDatabaseScope(selectedConnection, loadScans)`：拥有 schema、库表清单与勾选范围，启动采集时使用
  当前选中连接，发送 schemas 与带 schema 前缀的 tables，成功后刷新任务。
- `useDatabaseScans(selectedId, error)`：拥有连接详情、任务历史、详情抽屉与唯一的 5 秒轮询 timer。
  协调入口初次 load 完成后调用 startPolling，timer 在子 composable 的 onBeforeUnmount 清除。

`components/DatabaseConnectionForm.vue` 与 `DatabaseScanDetail.vue` 只展示，通过 props、v-model 与
save 事件和父页面连接；表单复用同一个响应式草稿，不复制口令。状态/结束原因的纯标签函数位于
`databaseConnectionPresentation.ts`，旧入口继续提供同名函数。页面不新增 API 调用或轮询。
本批保持原有请求及状态更新顺序；回归为 `database-connections-state.test.ts`（16 项）与
`database-connections-page.test.ts`（6 项），后者挂载真实 Element Plus 组件验证表单/抽屉与范围操作。
