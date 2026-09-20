# 项目状态

更新时间：2026-09-20。当前任务见 TASK.md；稳定约束见 AGENTS.md；模块关系见 docs/architecture.md。
历史时点数字与旧问题讨论已移至 [本批前完整状态](docs/history/project_status-before-data-asset-refactor-2026-09-19.md)。

## 版本与工作分支

| 项目 | 当前值 |
| --- | --- |
| 最近发布 | Git 注释标签 v2.12.0，发布提交 d1c1569 |
| 源码内平台版本 | 2.11.0（上一轮按不改代码约定保留，本轮不发新版本） |
| 探针源码版本 | 3.5.0；本轮未改探针或分发包 |
| 本批基线 / 分支 | 673e5f1 / refactor/data-asset-boundaries |
| 数据库迁移 | 0015_alert_hits；本批无模型/表结构变更 |
| 本批范围 | 第二十七批：前端流量视图页状态解耦；前二十六批（数据资产边界、分析编排与 Celery 入口、PCAP 域、文件域、平台资产域、事件/情报域、告警域、任务/审计/报表域、检测/引擎域、看板/流量视图域、探针域、集成与离线导入域、规则域、v1 剩余零散入口、PCAP 工作台状态、采集任务页状态、类型页状态、对象/实例详情页状态、扫描配置与规则版本页状态、文件分析/网络 DLP/敏感发现页状态、事件中心与告警中心页状态、资产中心页状态、检测中心页状态、引擎详情页状态、看板页状态、安全审计页状态）见下方记录 |

## 本批已落地结构

- 流量视图的状态收拢到
  `frontend/src/modules/network/traffic/composables/useLiveTraffic.ts`（77 行），页面只保留模板
  （`LiveTraffic.vue` 143 → 90 行）；去掉缩进后，迁入的 53 行脚本逐行未改，模板与样式逐字节未改。
- 实时告警流（`EventSource`）随状态进 composable：挂载时打开、卸载时关闭（`onBeforeUnmount`）、
  只保留最新 50 条、非法事件静默丢弃；页面保留路由与 `formatDateTime`/`formatBytes`。
- 行为不变：抓包速率仍从最近一次已分析捕获推导（无专门实时接口），无实时窗口时为 `null`；
  在线探针仍按 `status === 'online'` 过滤。注：`recentPcaps` 仍被加载但模板未渲染（与本批无关，
  保持原样）。
- 安全审计的状态收拢到 `frontend/src/modules/operations/audit/composables/useSecurityAudit.ts`
  （69 行），页面只保留模板（`SecurityAudit.vue` 167 → 121 行）；去掉缩进后，迁入的 50 行脚本逐行
  未改，模板与样式逐字节未改。
- 页面保留 `riskLabels` 静态标签与 `formatRiskScore`；审计汇总、日志分析输入/结果/错误，以及模板
  直接调用的 `matchGroups` 投影整块进 composable。
- 行为不变：汇总只读；日志为空（含只有空白）时不发请求；日志分析失败只进 `logError`，不动页面级
  `error`；`matchGroups` 仍按认证失败/端口扫描/提权/路径穿越的固定顺序输出并丢弃空分组。
- 看板的状态收拢到 `frontend/src/modules/dashboard/composables/useDashboard.ts`（94 行），页面只保留
  模板（`Dashboard.vue` 195 → 127 行）；去掉缩进后，迁入的 69 行脚本逐行未改，模板与样式逐字节未改。
- 页面保留路由与 `formatDateTime`/`formatRiskScore`（模板绑定，模板里的 `Incident`/`Asset` 类型注解
  也需要留在视图）；汇总卡、风险仪表、运行态、两条趋势与四个图表序列整块进 composable。
- 两处环形图仍共用 `levelBreakdown`：按 `severityOrder` 排序、用 `severityTagColors` 上色、丢弃计数为 0
  的档位，接口多出来的档位（如敏感类别的 `Unknown`）排在刻度之后；本批还删除了视图里因搬迁而不再
  使用的 `utils/mapping` 导入。
- 引擎详情的状态收拢到 `frontend/src/modules/engines/composables/useEngineDetail.ts`（114 行），
  页面只保留模板（`EngineDetail.vue` 208 → 126 行）；去掉缩进后，迁入的 83 行脚本逐行未改，
  模板与样式逐字节未改。
- composable 接收路由派生的 `name`（`ComputedRef<string>`），路由与导航留在页面；
  `executionLabels` 这类静态标签也留在视图；注册表解析、规则数与适配器匹配、规则清单分页与
  关键字筛选、发现列表与最近任务整块进 composable。
- 控制台路由名与发现里存的名字仍靠注册表对齐（`slug || name`，再退回同名匹配）；规则数仍先取
  注册表、再取同名适配器；本批还删除了视图里因搬迁而不再使用的 `EngineStatus` 类型导入。
- 检测中心的状态收拢到
  `frontend/src/modules/operations/detections/composables/useDetectionCenter.ts`（101 行），页面只保留
  模板（`DetectionCenter.vue` 183 → 111 行）；去掉缩进后，迁入的 78 行脚本逐行未改，模板逐字节未改。
- 页面保留 `filterFields`（引擎下拉的选项来自 composable 暴露的 `engineOptions`）与 `formatDateTime`；
  发现列表、详情抽屉与手动流水线整块进 composable，`ElMessage` 提示也留在 composable 里。
- 引擎下拉仍按 `detection_engine || name` 取值、标签取 `label || name` 并附发现数；注册表请求失败时
  选项保持为空，不影响发现列表加载。
- 资产中心的状态收拢到 `frontend/src/modules/asset/composables/useAssetCenter.ts`（171 行），
  页面只保留模板（`AssetCenter.vue` 290 → 147 行）；去掉缩进后，迁入的 145 行脚本逐行未改，
  模板逐字节未改（本批没有模板改动）。
- 页面保留 `filterFields` 与 `formatDateTime`/`formatRiskScore` 这类静态展示；资产列表、
  详情抽屉（含 `activeTab`/`detailLoading`）、关系图投影（`graphNodes`/`graphEdges`）与
  网络扫描控制台整块进 composable，`ElMessage` 提示也留在 composable 里。
- 扫描控制台的轮询（平台 240 次、探针 200 次，每次 3 秒）、终态判定、失败/超时提示与完成后重载
  列表随 `runScan()` 一起迁移；`discovery` 判定、端口解析（`parsePorts()`）与扫描阶段名脱敏
  （`nmap`/`nuclei`/`python-tcp`/`TCP-connect` → 服务检测）保持原逻辑。
- 本批唯一非机械改动：删除页面里从未使用的 `useRouter()`（模板与脚本都没有引用它）；
  `loadProbes` 只在 composable 的 `onMounted` 里调用，视图不再解构它。
- 事件中心与告警中心的状态收拢到
  `frontend/src/modules/operations/incidents/composables/useIncidentCenter.ts`（117 行）与
  `modules/operations/alerts/composables/useAlertCenter.ts`（84 行），两个页面只保留模板
  （`IncidentCenter.vue` 268 → 193、`AlertCenter.vue` 215 → 164 行）；去掉缩进后，被移动的
  75 行与 51 行脚本逐行未改，两个页面模板逐字节未改（本批没有模板改动）。
- 两个页面的筛选字段配置（`filterFields`）与攻击阶段标签（`stages`）留在视图，属于静态展示；
  `activeStages`/`findings`/`confidence` 这些投影随列表、详情、状态流转与
  `load`/`open`/`reset` 一起进 composable，`ElMessage` 提示也留在 composable 里。
- 事件中心的手工关联（`correlateOpen`/`correlateFindings`/`correlateWindow`/`correlateResult`
  与 `runCorrelate()`）整块迁入 composable，包含「发现必须是一个数组」的校验。
- 文件分析页、网络 DLP 页与敏感发现页的状态收拢到
  `frontend/src/modules/data-security/composables/useFileAnalysis.ts`（110 行）、
  `useNetworkDlp.ts`（106 行）与 `useSensitiveDiscovery.ts`（63 行），三个页面只保留模板
  （`FileAnalysis.vue` 185 → 115、`NetworkDlp.vue` 142 → 83、`SensitiveDiscovery.vue` 102 → 71 行）；
  去掉缩进后，被移动的 67 行、65 行与 36 行脚本逐行未改，三个页面模板全部逐字节未改
  （本批没有模板改动）。
- 文件分析的 4 秒抽屉刷新 timer 归 composable，页面卸载即停；网络 DLP 的 `evidenceRequest`
  竞态守卫随 `openTransfer()` 进 composable；`FileRecord`/`FileDetail` 由 composable 导出，
  视图按类型导入，这是唯一的修饰改动（两个接口加 `export`）。
- 敏感发现页的 `totals`/`entities`/`sources` 与图表投影仍全部来自服务端响应，不在前端重算；
  翻页沿用原有的 `onPageChange()`，因此模板无需改动。
- 数据安全域的前端页面到此全部完成状态解耦；其余前端页面按实际改动需求再拆。
- 扫描配置页与规则版本页的状态收拢到
  `frontend/src/modules/data-security/composables/useScanProfiles.ts`（188 行）与
  `useRuleVersions.ts`（141 行），两个页面只保留模板（`ScanProfiles.vue` 289 → 155、
  `RuleVersions.vue` 256 → 156 行）；去掉缩进后，被移动的 132 行与 96 行脚本逐行未改。
  扫描配置页只有一处声明过的改动：模板分页由
  `@current-change="(value: number) => { page = value; load() }"` 改为 `@current-change="setPage"`，
  把「移动分页」与「重新查询」放在一处；规则版本页模板逐字节未改。
- 扫描配置的草稿（`draft`、两个路径文本框、`editingId`）与新建/编辑/删除/下发弹窗都归 composable，
  `emptyDraft()` 与 `splitLines()` 一并在内；`ElMessage`/`ElMessageBox.confirm` 仍在 composable 里，
  与采集任务页保持一致。
- 规则版本页把探针侧「已观测到的版本」分类（`syncedProbes`/`outOfDateProbes`/`failedProbes`）与
  `probedVersion`/`probeField`/`shortHash` 一起进 composable，页面只渲染。
- 删除第十七批遗留的「前端对象详情与实例详情页尚未拆分」，该句在第十八批已完成。
- 数据对象详情与实例详情的状态收拢到
  `frontend/src/modules/data-security/composables/useDataObjectDetail.ts`（104 行）与
  `useAssetInstanceDetail.ts`（72 行），两个页面只保留模板、行跳转与时间格式化
  （`DataObjectDetail.vue` 219 → 159、`AssetInstanceDetail.vue` 193 → 153 行）；被移动的 61 行与
  40 行脚本逐行未改，只有两处声明过的改动：路由 id 以 `ComputedRef` 参数传入（composable 不再自己
  `useRoute`），以及对象页新增 `setDetectionPage()`——模板原来的
  `@current-change="(value) => { detectionPage = value; loadDetections() }"` 改为
  `@current-change="setDetectionPage"`，composable 返回的 ref 不能在模板里直接赋值
  （同 PCAP 批的 `closeFileDialog`）。
- 证据抽屉的打开、加载与失败状态随域进 composable，页面不再各自维护一份；实例页的
  `formatTime`/`formatMtime` 属于纯展示，留在视图，`includeHistory` 与重查逻辑进 composable。
- 数据目录四个页面（类型中心、类型详情、对象详情、实例详情）与采集任务页已完成状态解耦；
  前端其余页面按实际改动需求再拆。
- 数据类型中心与类型详情的状态收拢到
  `frontend/src/modules/data-security/composables/useDataTypeCenter.ts`（64 行）与
  `useDataTypeDetail.ts`（68 行），两个页面只保留模板（`DataTypeCenter.vue` 154 → 117、
  `DataTypeDetail.vue` 134 → 99 行）；被移动的 37 行与 35 行脚本逐行未改，只有两处声明过的改动：
  类型详情把路由 `category` 作为 `ComputedRef` 参数传入（composable 不再自己 `useRoute`），以及新增
  `setPage()`——模板原来的 `@current-change="(value) => (page = value)"` 改为 `@current-change="setPage"`，
  composable 返回的 ref 不能在模板里直接赋值（同 PCAP 批的 `closeFileDialog`）。
- 类型页顶部卡片仍直接用服务端去重后的 `totals`/`totals_scope`，不把每行的 `object_count` 相加；
  一次失败的刷新保留上一次成功的数据，不把范围清空成假象。
- 前端数据资产采集任务页的状态与 API 编排收拢到
  `frontend/src/modules/data-security/composables/useDataAssetJobs.ts`（159 行），
  `DataAssetJobs.vue` 只保留模板与按钮（251 → 131 行）；被移动的 113 行脚本除下面一处逐行未改：
  任务列表原来由页面直接调 `apiGet('/tasks', ...)`，改用 `api/tasks.ts::listTasks`（同一个请求）。
- 派发/取消/移除、探针与扫描配置下拉、统计卡计数与 5 秒自动刷新的 timer 都在 composable 里：
  `onMounted` 启动轮询、`onBeforeUnmount` 清除，离开页面即停止轮询；派发 payload 语义不变
  （显式路径优先于扫描配置，路径非空且选了配置时两个字段都发，未选探针不发请求）。
- 前端 PCAP 工作台的状态与 API 编排收拢到
  `frontend/src/modules/network/pcap/composables/usePcapWorkbench.ts`（382 行），
  `PcapWorkbench.vue` 只保留模板、弹窗与格式化（582 → 312 行）；被移动的 278 行脚本除下面两处
  逐行未改：`streamData` 改用 `api/pcaps.ts` 已有的 `TcpStreamFollow` 类型（去掉重复的内联类型），
  以及新增 `closeFileDialog()`（模板原来直接 `++fileVersion`，而 `let` 计数器无法从 composable 的
  返回值暴露成活的绑定，直接自增会丢掉“关弹窗即作废在途预览”的语义）。
- 过期响应防护与轮询语义原样保留：`viewVersion`（切换抓包）、`packetVersion`（包分页）、
  `detailVersion`（包详情）、`fileVersion`（文件预览）、`taskVersion`（分析轮询），
  轮询 timer 在组件卸载时清除，离开页面即停止轮询；API 仍只走 `frontend/src/api`，未新增 HTTP 客户端。
- `api/v1.py` 里最后的零散入口按域收拢，`v1.py` 自此**只做子路由聚合**（自身不再声明任何路径，
  288 → 79 行）：`api/auth.py`（3 条路径：`POST /auth/login`、`POST /auth/logout`、`GET /auth/me`）、
  `api/health.py`（`GET /health`）、`api/network_scan.py`（`POST /scan`、`GET /scan/{task_id}`）、
  `api/test_data.py`（`POST /test/import`、`POST /test/clear`、`GET /test/status`）。
- 共享边界一律复用不复制：会话/口令仍走 `core/security.py` 与 `AdminSession`；`/health` 的
  worker 能力与规则清单仍读 `api/runtime_status.py`（与 `/integrations` 共用一份）；`/scan` 的
  端口选择走 `services/scan_service.py`、探针侧排队走 `services/probe_task_service.py`、派发走
  `api/dependencies.dispatch_task`；测试数据的导入/清理/状态仍在 `services/test_service.py`。
- 写入口的 opt-in 守卫 `_require_test_data_import`（读 `settings.test_data_import_enabled`，
  默认关闭）随域下沉到 `api/test_data.py`，两个写入口都必须先过守卫；`main.py` 对
  `/api/v1/health` 的免鉴权放行、`/api/v1/auth/login` 的公开例外与探针路径判定均未改动。
- 四条路径无 tag、无参数变化，OpenAPI 拆分前后**完全一致**（144 条路径 / 158 个操作，含路径顺序）；
  路由仍 162 条记录（158 APIRoute），路径/方法/端点函数名多重集与拆分前完全相同，仅注册顺序变化。
- 检测引擎规则面收拢为 `api/rules.py`（5 条路径：`GET /rules`、`GET /rules/content`、`GET /rule-sources`、
  `POST /rules/sync`、`POST /rules`），其中后三条原在 `api/libraries.py`，本批归位后该文件只保留
  敏感数据（DLP）规则族 `/dlp/rules*`（217 → 101 行）；`RuleSyncRequest`、`DetectionRule` 两个请求模型
  随域下沉。
- 规则枚举仍只有 `api/rule_presenter.py::rule_file_entries` 一份实现（`/engine/registry` 共用），
  来源出处读 `app.rules.catalog`/`app.rules.library`，在线拉取走 `app.rules.sync`，
  手工 Suricata/YARA 导入仍走 `app.integrations.offline_manager` 与 `yara` 校验，
  `record_audit` 审计不变；本域不新增任何序列化或校验副本。
- 从 `libraries.py` 迁出的三条路由保留原 `rule-libraries` tag，OpenAPI 拆分前后排序后**字节一致**。
- 第十二批边界维持：集成与离线导入域在 `api/integrations.py`（11 条路径），`libraries.py` 不再有
  `/offline*`；worker 能力/规则清单读取仍在 `api/runtime_status.py`。
- 适配器目录/手动执行与整个 `/offline` 面收拢为 `api/integrations.py`（11 条路径：`GET /integrations`、
  `POST /integrations/{name}/analyze`、`POST /integrations/offline/upload|import`、
  `GET /offline/resources`、`GET|POST /offline/cves`、`POST /offline/upload`、
  `POST /offline/grype/update|import`、`GET /offline/grype/jobs/{identifier}`）。
  `/offline/*` 原先分散在 `api/v1.py`（资源/CVE 列表、上传）与 `api/libraries.py`（手工 CVE、Grype 任务），
  本批归位后 `libraries.py` 只保留 dlp 规则、规则源与规则导入（302 → 217 行），
  被迁走的 `CveRule`、`job_path`、`run_grype_job` 随域下沉。
- worker 能力与规则清单读取（原 v1 私有 `_read_worker_capabilities`、`_merge_capability`、
  `_engine_rule_counts`）下沉到共享 `api/runtime_status.py`（公开为 `read_worker_capabilities`、
  `merge_capability`、`engine_rule_counts`），`/health` 与 `/integrations` 共用一份实现；
  v1 侧随之删除已无使用者的 `incident_engine = IncidentEngine()` 句柄（`incident_engine` 逻辑不变）。
- 从 `libraries.py` 迁出的四条 `/offline` 路由保留历史上的 `rule-libraries` tag，OpenAPI 拆分前后
  排序后**字节一致**（含 tags），不是行为改动。
- 第十一批边界维持：探针域路由在 `api/probes.py`（9 条路径），探针鉴权/登记/删除/卸载/任务行仍在
  `core/security.py`、`api/dependencies.py`、`deployment/*`、`services/probe_service.py`、`services/task_service.py`。
- 探针注册/心跳/列表/删除/分析/扫描/指标与加密画像独立为 `api/probes.py`（9 条路径：`/probes/register`、
  `/probes/{probe_id}/heartbeat`、`/probes`、`/probes/{probe_id}`、`/probes/{probe_id}/analyze`、
  `/probes/{probe_id}/tasks`、`/probes/{probe_id}/scan`、`/probes/{probe_id}/metrics`、
  `/crypto/probe-profile`），连同本域私有辅助 `_merge_metadata`、`_latest_ruleset_version`、
  `_probe_removal_target` 一并下沉；探针鉴权（`core/security.py`、`api/dependencies.py`）、
  登记入册（`deployment/enrollment.py`）、删除与远端卸载（`services/probe_service.py`、
  `deployment/removal.py`）、任务行（`services/task_service.py`）仍在原处，只做 HTTP 边界。
- 本域原先在 v1 内用的私有派发 `_dispatch(task_id, 注册名, ...)` 下沉为共享
  `api/dependencies.py::dispatch_task`（docstring 原样保留，参数顺序不变），v1 不再保留副本；
  另按 ruff B904 把随域移动的两处 `raise HTTPException(...)` 补为 `raise ... from exc`（异常类型与状态码不变）。
- 第十批边界维持：看板、风险总览、关系图与全局流量视图在 `api/dashboard.py`（13 条路径），
  全部数字仍由 `app/models.py` 的行实时聚合，未新增缓存或派生表。
- 看板、风险总览、关系图与全局流量视图独立为 `api/dashboard.py`（13 条路径：`/risk/summary`、`/graph`、
  `/dashboard/summary|risk-trend|severity|engines|incidents|high-risk-assets|sensitive-data|incident-trend`、
  `/flows`、`/protocols`、`/network/live`），全部数字仍由 `app/models.py` 的行实时聚合，未新增缓存或派生表。
- 行序列化继续复用 `api/assets.py::serialize_asset`、`api/incident_presenter.py::serialize_incident`、
  `api/pcaps.py::serialize_flow`、`api/probe_presenter.py::serialize_probe`，协议分层复用
  `services/protocol_service.py::protocol_layer`，分页复用 `api/pagination.py`。
- 第九批边界维持：检测结果路由在 `api/detections.py`（3 条路径）、引擎路由在 `api/engines.py`（2 条路径），
  引擎清单/规则清单分别读 `app.engine.registry` 与 `api/rule_presenter.py::rule_file_entries`。
- 第七批边界维持：告警域路由在 `api/alerts.py`（5 条路径），抑制合并/命中聚合/投递在
  `services/alert_service.py`，探针行与规则解析在 `api/probe_presenter.py`、`api/rule_presenter.py`。
- 第五、六批边界维持：平台资产域路由在 `api/assets.py`（4 条路径，导出 `serialize_asset`），
  事件/情报域路由在 `api/incidents.py`（7 条路径），关联计算仍在 `incident_engine`，
  行序列化在 `api/*_presenter.py`，列表时间过滤在 `api/query_filters.py::string_time_filter`。
- 第四批边界维持：文件证据域路由在 `api/files.py`（5 条路径，含扩展名/MIME 过滤器与 `serialize_file`），
  上传归属用 `api/dependencies.py::upload_probe_id`，Task 行序列化用 `api/task_presenter.py::serialize_task`。
- 第三批边界维持：PCAP 域路由在 `api/pcaps.py`（18 条路径，含文件末尾兼容下载端点），上传归属与队列背压
  在 `api/dependencies.py`，Task 行序列化在 `api/task_presenter.py`，PCAP 域与 tasks 路由共用同一实现。
- 第二批边界维持：平台资产/IOC 身份解析（`domain/evidence_identity.py`）、跨域分析编排
  （`application/analysis.py`）、任务行持久化（`services/task_service.py`）与队列派发端口
  （`services/task_dispatch.py`）分层独立；worker 分 analysis/notification/maintenance 三模块，
  加 `task_runtime.py`、`task_names.py`；旧 `workers/tasks.py` 仅 43 行兼容门面；API 不再导入 `app.workers.*`。
- 第一批边界维持：采集 schema/路由/任务创建/错误映射独立，数据对象按职责分模块，旧服务文件仅兼容导出；
  旧资产展示与敏感发现路由在 data_assets，前端 DataAsset 页面仅组装列表/详情与采集状态。
- 具体功能修改入口见 [数据资产开发入口](docs/数据资产开发入口.md)。

| 文件 | 拆分前行数（首次） | 当前行数 |
| --- | ---: | ---: |
| frontend/src/modules/network/traffic/LiveTraffic.vue | 143 | 90 |
| frontend/src/modules/network/traffic/composables/useLiveTraffic.ts | 0（本批新增） | 77 |
| frontend/src/modules/operations/audit/SecurityAudit.vue | 167 | 121 |
| frontend/src/modules/operations/audit/composables/useSecurityAudit.ts | 0（本批新增） | 69 |
| frontend/src/modules/dashboard/Dashboard.vue | 195 | 127 |
| frontend/src/modules/dashboard/composables/useDashboard.ts | 0（本批新增） | 94 |
| frontend/src/modules/engines/EngineDetail.vue | 208 | 126 |
| frontend/src/modules/engines/composables/useEngineDetail.ts | 0（本批新增） | 114 |
| frontend/src/modules/operations/detections/DetectionCenter.vue | 183 | 111 |
| frontend/src/modules/operations/detections/composables/useDetectionCenter.ts | 0（本批新增） | 101 |
| frontend/src/modules/asset/AssetCenter.vue | 290 | 147 |
| frontend/src/modules/asset/composables/useAssetCenter.ts | 0（本批新增） | 171 |
| frontend/src/modules/operations/incidents/IncidentCenter.vue | 268 | 193 |
| frontend/src/modules/operations/alerts/AlertCenter.vue | 215 | 164 |
| frontend/src/modules/operations/incidents/composables/useIncidentCenter.ts | 0（本批新增） | 117 |
| frontend/src/modules/operations/alerts/composables/useAlertCenter.ts | 0（本批新增） | 84 |
| frontend/src/modules/data-security/FileAnalysis.vue | 185 | 115 |
| frontend/src/modules/data-security/NetworkDlp.vue | 142 | 83 |
| frontend/src/modules/data-security/SensitiveDiscovery.vue | 102 | 71 |
| frontend/src/modules/data-security/composables/useFileAnalysis.ts | 0（本批新增） | 110 |
| frontend/src/modules/data-security/composables/useNetworkDlp.ts | 0（本批新增） | 106 |
| frontend/src/modules/data-security/composables/useSensitiveDiscovery.ts | 0（本批新增） | 63 |
| frontend/src/modules/data-security/ScanProfiles.vue | 289 | 155 |
| frontend/src/modules/data-security/RuleVersions.vue | 256 | 156 |
| frontend/src/modules/data-security/composables/useScanProfiles.ts | 0（本批新增） | 188 |
| frontend/src/modules/data-security/composables/useRuleVersions.ts | 0（本批新增） | 141 |
| frontend/src/modules/data-security/DataObjectDetail.vue | 219 | 159 |
| frontend/src/modules/data-security/AssetInstanceDetail.vue | 193 | 153 |
| frontend/src/modules/data-security/composables/useDataObjectDetail.ts | 0（本批新增） | 104 |
| frontend/src/modules/data-security/composables/useAssetInstanceDetail.ts | 0（本批新增） | 72 |
| frontend/src/modules/data-security/DataTypeCenter.vue | 154 | 117 |
| frontend/src/modules/data-security/DataTypeDetail.vue | 134 | 99 |
| frontend/src/modules/data-security/composables/useDataTypeCenter.ts | 0（本批新增） | 64 |
| frontend/src/modules/data-security/composables/useDataTypeDetail.ts | 0（本批新增） | 68 |
| frontend/src/modules/data-security/DataAssetJobs.vue | 251 | 131 |
| frontend/src/modules/data-security/composables/useDataAssetJobs.ts | 0（本批新增） | 159 |
| backend/app/api/v1.py | 2557 | 288 |
| backend/app/api/rules.py | 0（本批新增） | 197 |
| backend/app/api/libraries.py | 302 | 101 |
| backend/app/api/integrations.py | 0（本批新增） | 318 |
| backend/app/api/runtime_status.py | 0（本批新增） | 75 |
| backend/app/api/probes.py | 0（本批新增） | 370 |
| backend/app/api/dependencies.py | 12 | 60 |
| backend/app/api/dashboard.py | 0（本批新增） | 403 |
| backend/app/api/detections.py | 0（第九批新增） | 110 |
| backend/app/api/engines.py | 0（第九批新增） | 110 |
| backend/app/api/tasks.py | 0（第八批新增） | 104 |
| backend/app/api/reports.py | 0（第八批新增） | 175 |
| backend/app/api/alerts.py | 0（本批新增） | 252 |
| backend/app/api/rule_presenter.py | 0（本批新增） | 241 |
| backend/app/api/probe_presenter.py | 0（本批新增） | 35 |
| backend/app/api/incidents.py | 0（第六批新增） | 162 |
| backend/app/api/query_filters.py | 0（第六批新增） | 11 |
| backend/app/api/assets.py | 0（第五批新增） | 238 |
| backend/app/api/incident_presenter.py | 0（第五批新增） | 55 |
| backend/app/api/ioc_presenter.py | 0（第五批新增） | 22 |
| backend/app/core/datetimes.py | 0（第五批新增） | 25 |
| backend/app/api/files.py | 0（第四批新增） | 206 |
| backend/app/api/pcaps.py | 0（第三批新增） | 649 |
| backend/app/api/task_presenter.py | 0（第三批新增） | 25 |
| backend/app/api/extensions.py | 718 | 364 |
| backend/app/services/data_object_service.py | 1165 | 58（兼容导出） |
| backend/app/workers/tasks.py | 981 | 43（兼容门面） |
| backend/app/incident_engine/engine.py | 344 | 263（身份解析移出） |
| frontend/src/modules/data-security/DataAsset.vue | 285 | 144 |

逻辑被移动到有明确职责的模块，不是删除功能；不得用总行数变化代替维护效率评估。

## 验证与已知限制

- 第二十七批（前端）：`npm run typecheck` 通过；全量 vitest 24 个文件 184 项通过（原 176 项 + 本批新增
  `live-traffic-state.test.ts` 8 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：去掉缩进后，迁入 composable 的 53 行脚本逐行未改，模板与样式逐字节未改。
- 第二十七批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `LiveTraffic`/`SecurityAudit` chunk 均 200，
  chunk 名与本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；回退标签
  `source-frontend:pre-live-traffic-state-20260920`。
- 第二十七批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/network/live`（窗口 300s、连接 214、包 536、pps 1.79、bps 1553.67、在线探针 1）、`/pcaps`、
  `/alerts/summary`、`/probes`、`/flows`、`/protocols`、`/audit/summary`、`/dashboard/summary`、
  `/risk/summary`、`/engine/registry`、`/detections`、`/assets`、`/incidents`、`/alerts`、`/files`、
  `/dlp/policy`、`/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、
  `/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；未订阅真实告警流
  （`/alerts/stream` 未连接）、未调用测试数据导入接口、未操作真实探针主机，迁移仍 `0015_alert_hits`
  （head）。
- 第二十六批（前端）：`npm run typecheck` 通过；全量 vitest 23 个文件 176 项通过（原 169 项 + 本批新增
  `security-audit-state.test.ts` 7 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：去掉缩进后，迁入 composable 的 50 行脚本逐行未改，模板与样式逐字节未改。
- 第二十六批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `SecurityAudit`/`Dashboard` chunk 均 200，
  chunk 名与本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；回退标签
  `source-frontend:pre-security-audit-state-20260920`。
- 第二十六批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/audit/summary`（资产 214、文件 1、PCAP 3996、异常 9；资产风险 Medium 33 / High 13 / Low 168；
  异常等级 High 9；泄漏风险 High，高危协议 `http`），以及 `/dashboard/summary`、`/risk/summary`、
  `/engine/registry`、`/detections`、`/rulesets`、`/tasks`、`/assets`、`/probes`、`/incidents`、
  `/alerts`、`/alerts/summary`、`/files`、`/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、
  `/scan-profiles`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、
  `/sensitive/findings`、`/sensitivity-levels` 均 200；本批未 `POST /audit/logs`（保持只读），
  未导入测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 第二十五批（前端）：`npm run typecheck` 通过；全量 vitest 22 个文件 169 项通过（原 162 项 + 本批新增
  `dashboard-state.test.ts` 7 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：去掉缩进后，迁入 composable 的 69 行脚本逐行未改，模板与样式逐字节未改。
- 第二十五批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `Dashboard`/`EngineDetail` chunk 均 200，
  chunk 名与本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；回退标签
  `source-frontend:pre-dashboard-state-20260920`。
- 第二十五批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/dashboard/summary`（告警 479、开放告警 475、事件 208、高危检测 3266、高风险资产 13、敏感数据资产
  33、在线探针 1、健康集成 4）、`/risk/summary`（3614 条：Critical 234 / High 3032 / Medium 339 /
  Low 9）、`/dashboard/risk-trend`、`/dashboard/incident-trend`、`/dashboard/severity`、
  `/dashboard/engines`、`/dashboard/incidents`、`/dashboard/high-risk-assets`、`/dashboard/sensitive-data`
  （含 `Unknown` 这类额外档位），以及 `/engine/registry`、`/detections`、`/assets`、`/probes`、
  `/incidents`、`/alerts`、`/alerts/summary`、`/files`、`/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、
  `/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、
  `/sensitive/findings`、`/sensitivity-levels` 均 200；未调用测试数据导入接口，未操作真实探针主机，
  迁移仍 `0015_alert_hits`（head）。
- 第二十四批（前端）：`npm run typecheck` 通过；全量 vitest 21 个文件 162 项通过（原 151 项 + 本批新增
  `engine-detail-state.test.ts` 11 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：去掉缩进后，迁入 composable 的 83 行脚本逐行未改，模板与样式逐字节未改。
- 第二十四批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `EngineDetail`/`EnginesOverview` chunk
  均 200，chunk 名与本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；回退标签
  `source-frontend:pre-engine-detail-state-20260920`。
- 第二十四批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/engine/registry`（15 个引擎，`sigma_log_engine` 的 `slug=sigma`、`rule_count=2949`）、
  `/integrations`、`/tasks`、`/detections`、`/rules?engine=sigma_log_engine&include_content=false`，
  以及 `/assets`、`/probes`、`/incidents`、`/alerts`、`/alerts/summary`、`/files`、`/dlp/*`、
  `/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、
  `/sensitive/findings`、`/sensitivity-levels` 均 200；未调用测试数据导入接口，未操作真实探针主机，
  迁移仍 `0015_alert_hits`（head）。
- 第二十三批（前端）：`npm run typecheck` 通过；全量 vitest 20 个文件 151 项通过（原 141 项 + 本批新增
  `detection-center-state.test.ts` 10 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：去掉缩进后，迁入 composable 的 78 行脚本逐行未改，模板逐字节未改。
- 第二十三批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `DetectionCenter` chunk 均 200，chunk 名与
  本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；回退标签
  `source-frontend:pre-detection-centre-state-20260920`。
- 第二十三批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/detections`（3606 条）、`/detections/{id}`（37 个关联事件、9 项证据、命中 alert）、
  `/engine/registry`（15 个引擎），以及 `/assets`、`/probes`、`/incidents`、`/alerts`、
  `/alerts/summary`、`/files`、`/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、`/scan-profiles`、
  `/rulesets`、`/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、`/sensitive/findings`、
  `/sensitivity-levels` 均 200；未调用测试数据导入接口，未操作真实探针主机，迁移仍
  `0015_alert_hits`（head）。
- 第二十二批（前端）：`npm run typecheck` 通过；全量 vitest 19 个文件 141 项通过（原 126 项 + 本批新增
  `asset-center-state.test.ts` 15 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：去掉缩进后，迁入 composable 的 145 行脚本逐行未改，模板逐字节未改。
- 第二十二批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `AssetCenter` chunk 均 200，chunk 名与
  本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；回退标签
  `source-frontend:pre-asset-centre-state-20260920`。
- 第二十二批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/assets`（214 条）、`/assets/{id}`（findings 100、incidents 28、relations 200）、`/probes`（1 台
  `test123` online）、`/incidents`、`/alerts`、`/alerts/summary`、`/files`、`/dlp/policy`、
  `/dlp/transfers`、`/dlp/rules`、`/scan-profiles`、`/rulesets`、`/data/assets`、`/data-types`、
  `/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；未调用
  测试数据导入接口，未操作真实探针主机，迁移仍 `0015_alert_hits`（head）。
- 第二十一批（前端）：`npm run typecheck` 通过；全量 vitest 18 个文件 126 项通过（原 109 项 + 本批新增
  `incident-alert-center-state.test.ts` 17 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：去掉缩进后，两个页面迁入 composable 的 75 行与 51 行脚本逐行未改，模板逐字节未改。
- 第二十一批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `IncidentCenter`/`AlertCenter` chunk
  均 200，chunk 名与本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；
  回退标签 `source-frontend:pre-incident-alert-center-state-20260920`。
- 第二十一批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/incidents`、`/incidents/{id}`、`/alerts`、`/alerts/{id}`、`/alerts/summary`、`/files`、
  `/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、`/scan-profiles`、`/rulesets`、`/probes`、
  `/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、`/sensitive/findings`、
  `/sensitivity-levels` 均 200；未调用测试数据导入接口，未操作真实探针主机，迁移仍
  `0015_alert_hits`（head）。
- 第二十批（前端）：`npm run typecheck` 通过；全量 vitest 17 个文件 109 项通过（原 87 项 + 本批新增
  `file-analysis-state.test.ts` 9 项与 `network-dlp-discovery-state.test.ts` 13 项）；生产构建
  `npm run build`（未启用 `VITE_DEMO_MODE`）通过。逐行比对：去掉缩进后，三个页面迁入 composable 的
  67 行、65 行与 36 行脚本逐行未改，三个页面模板逐字节未改。
- 第二十批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `FileAnalysis`/`NetworkDlp`/
  `SensitiveDiscovery` chunk 均 200，chunk 名与本地构建一致、线上字节与本地构建 SHA256 相同、
  无 demo/mock 代码；回退标签 `source-frontend:pre-data-security-pages-state-20260920`。
- 第二十批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/files`、`/files/{id}`、`/dlp/policy`、`/dlp/transfers`、`/dlp/rules`、`/scan-profiles`、
  `/rulesets`、`/tasks?kind=data_asset_scan`、`/probes`、`/data/assets`、`/data-types`、
  `/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；
  未调用测试数据导入接口，未操作真实探针主机，迁移仍 `0015_alert_hits`（head）。
- 第十九批（前端）：`npm run typecheck` 通过；全量 vitest 15 个文件 87 项通过（原 70 项 + 本批新增
  `scan-profile-rule-version-state.test.ts` 17 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：去掉缩进后，两个页面迁入 composable 的 132 行与 96 行脚本逐行未改；规则版本页模板
  逐字节未改，扫描配置页模板只改了分页那一行。
- 第十九批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `ScanProfiles`/`RuleVersions` chunk
  均 200，chunk 名与本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；
  回退标签 `source-frontend:pre-scan-profile-rule-version-state-20260920`。
- 第十九批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/scan-profiles`、`/rulesets`、`/rulesets/{id}/versions`、`/tasks?kind=data_asset_scan`、`/probes`、
  `/data/assets`、`/data-types`、`/data-objects`、`/asset-instances`、`/sensitive/findings`、
  `/sensitivity-levels` 均 200；未调用测试数据导入接口，未操作真实探针主机，迁移仍
  `0015_alert_hits`（head）。
- 第十八批（前端）：`npm run typecheck` 通过；全量 vitest 14 个文件 70 项通过（原 62 项 + 本批新增
  `data-object-instance-state.test.ts` 8 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：两个页面迁入 composable 的 61 行与 40 行脚本逐行未改，模板除对象页分页的
  `@current-change` 外逐字节未改。
- 第十八批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `DataObjectDetail`/`AssetInstanceDetail`
  chunk 均 200，chunk 名与本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；
  回退标签 `source-frontend:pre-data-object-instance-state-20260920`。
- 第十八批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/tasks?kind=data_asset_scan`、`/probes`、`/scan-profiles`、`/data/assets`、`/data-types`、
  `/data-types/address`、`/data-objects`、`/data-objects/{id}`、`/data-objects/{id}/detections`、
  `/asset-instances`、`/asset-instances/{id}`（含 `include_history=true`）、`/detections/{id}/evidence`、
  `/sensitive/findings`、`/sensitivity-levels` 均 200；未调用测试数据导入接口，未操作真实探针主机，
  迁移仍 `0015_alert_hits`（head）。
- 第十七批（前端）：`npm run typecheck` 通过；全量 vitest 13 个文件 62 项通过（原 55 项 + 本批新增
  `data-type-catalog-state.test.ts` 7 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：两个页面迁入 composable 的 37 行与 35 行脚本逐行未改，模板除类型详情分页的
  `@current-change` 外逐字节未改。
- 第十七批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `DataTypeCenter`/`DataTypeDetail` chunk
  均 200，chunk 名与本地构建一致、线上字节与本地构建 SHA256 相同、无 demo/mock 代码；回退标签
  `source-frontend:pre-data-type-catalog-state-20260920`。
- 第十七批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/tasks?kind=data_asset_scan`、`/probes`、`/scan-profiles`、`/data/assets`、`/data-types`、
  `/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；
  未调用测试数据导入接口，未操作真实探针主机，迁移仍 `0015_alert_hits`（head）。
- 第十六批（前端）：`npm run typecheck` 通过；全量 vitest 12 个文件 55 项通过（原 46 项 + 本批新增
  `data-asset-jobs-state.test.ts` 9 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：迁入 composable 的 113 行脚本除 1 处声明过的改动（`apiGet('/tasks', ...)` 改用
  `api/tasks.ts::listTasks`，同一个请求）外与拆分前完全一致；模板与样式区域逐字节未改。
- 第十六批镜像（前端）：legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/`、入口 chunk 与 `DataAssetJobs` chunk 均 200，
  线上 chunk 与本地构建 SHA256 相同、无 demo/mock 代码；回退标签
  `source-frontend:pre-data-asset-jobs-state-20260920`。
- 第十六批真实环境只读复验（后端未改）：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/tasks?kind=data_asset_scan`、`/probes`、`/scan-profiles`、`/data/assets`、`/data-types`、
  `/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；
  未调用测试数据导入接口，未操作真实探针主机，迁移仍 `0015_alert_hits`（head）。
- 第十五批（前端）：`npm run typecheck` 通过；全量 vitest 11 个文件 46 项通过（原 37 项 + 本批新增
  `pcap-workbench-state.test.ts` 9 项）；生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
  逐行比对：迁入 composable 的 278 行脚本除 2 处声明过的改动（`streamData` 用 `TcpStreamFollow`、
  新增 `closeFileDialog()`）外与拆分前完全一致。
- 第十五批镜像（前端）：用同一 builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器
  未重建）：容器 Up，`http://localhost:8088/` 与入口 chunk、`PcapWorkbench` chunk 均 200，
  入口 chunk 名与本地构建一致；工作台 chunk 内仍是真实 API 调用、无 demo/mock 代码。
  回退标签 `source-frontend:pre-pcap-workbench-state-20260920`。
- 第十四批（本机 .venv 隔离全量）726 项：719 passed / 6 failed / 1 skipped；6 项失败与第十三批
  基线集合完全相同，无新增失败、无新增错误（其中 29 项为本批新增边界测试）。拆分前后 OpenAPI
  **完全一致**（144 条路径 / 158 个操作，含路径顺序与 tags）；路由仍 162 条记录（158 APIRoute）、
  158 条「路径 + 方法」多重集与拆分前相同；158 个操作的「方法 + 路径」首个命中函数完全一致；
  10 个被移动定义的 AST 逐节点比对完全相同；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- `v1.py` 迁出的 10 个定义（`admin_login`、`admin_logout`、`admin_me`、`health`、`start_scan`、
  `scan_result`、`_require_test_data_import`、`import_test`、`clear_test`、`get_test_status`）AST
  逐节点比对与拆分前完全相同；`v1.py` 自此不再定义任何路由函数，只剩聚合。
- 测试迁移与新增：新增 `tests/test_auth_boundaries.py`（7 项）、`tests/test_health_boundaries.py`（7 项）、
  `tests/test_network_scan_boundaries.py`（8 项）、`tests/test_test_data_boundaries.py`（7 项）；
  `tests/test_integration_offline_boundaries.py` 的 worker 能力共用断言由 `v1.py` 改指 `api/health.py`
  （`/health` 迁出后 v1 不再导入 `runtime_status`）。
- `v1.py` ruff 存量 23 → 0（14 E501 → 0、9 B008 → 0），四个新模块与四个新测试 ruff check/format
  一次通过；未对老文件做批量重排，只清理了拆分后无处使用的导入。
- 第十三批（本机 .venv 隔离全量）697 项：690 passed / 6 failed / 1 skipped；6 项失败与第十二批基线集合完全相同，
  无新增失败、无新增错误（其中 8 项为本批新增边界测试）。拆分前后 OpenAPI **排序后字节一致**
  （144 条路径 / 158 个操作，含迁出三条路由的 `tags`）；路由仍 162 条记录（158 APIRoute）、
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；158 个操作的「方法 + 路径」首个命中函数完全一致；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 规则域 AST 逐节点比对：7 个移动定义中 `list_rules`、`rule_content`、`RuleSyncRequest`、`DetectionRule`
  与拆分前完全相同，另 3 处差异仅为迁出路由保留 `rule-libraries` tag；`v1.py` 与 `libraries.py`
  分别只少 2 个与 5 个定义，无其他改动。
- `v1.py` ruff 存量 26 → 23（15 E501 → 14、11 B008 → 9），`libraries.py` 11 → 5（5 B008 → 2、4 E501 → 2、
  2 I001 → 1），均只减不增；新增模块与新增测试 ruff check/format 通过。
- 既有 flaky（与本批无关，结构移动不修）：`tests/deployment/test_credential.py::test_tamper_rejected`
  用 `ciphertext[:-1] + b"\x00"` 制造篡改，当密文最后一个字节本身就是 `0x00` 时篡改等于没改，
  解密成功、`pytest.raises` 不触发（实测 3000 次里 12 次、约 1/256）。单独运行该文件必过；
  全量偶发多出 1 项失败即由此而来，不要误判为重构回归。
- 第十二批（本机 .venv 隔离全量）688 项：681 passed / 6 failed / 1 skipped；6 项失败与第十一批基线集合完全相同，
  无新增失败、无新增错误（其中 8 项为本批新增边界测试）。拆分前后 OpenAPI **排序后字节一致**
  （144 条路径 / 158 个操作，含从 `libraries.py` 迁出的四条路由的 `tags`）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；`/integrations*` 与 `/offline*` 由 v1 中段与
  libraries 段集中到 v1 末尾随子路由注册，逐条比对 158 个操作的「方法 + 路径」首个命中函数与拆分前完全一致；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 集成/离线导入域 AST 逐节点比对：14 个移动定义（`list_integrations`、`run_integration`、`upload_offline`、
  `import_offline`、`offline_resources`、`offline_cves`、`upload_offline_alt`、`CveRule`、`add_cve`、
  `job_path`、`run_grype_job`、`update_grype`、`upload_grype`、`grype_job`）中 9 个与拆分前完全相同，
  另 5 处差异全部是本批声明过的改动：`list_integrations` 的三处共享助手改名，以及四条迁出路由新增
  `tags=["rule-libraries"]`（为保持 OpenAPI 不变）；三个能力助手在改名后与拆分前逐节点一致。
- 测试迁移：`tests/test_rule_libraries.py` 的独立 app 现在同时挂 `libraries` 与 `integrations`
  子路由；`tests/test_gap_fixes.py` 的 monkeypatch 目标由 `app.api.v1` 改到真实查找位置
  `app.api.integrations`（与 PCAP/探针批同一约定）。
- `v1.py` ruff 存量 46 → 26（27 E501 → 15、19 B008 → 11），`libraries.py` 15 → 11（7 B008 → 5、6 E501 → 4），
  均只减不增；新增模块与新增测试 ruff check/format 通过。
- 第十一批（本机 .venv 隔离全量）680 项：673 passed / 6 failed / 1 skipped；6 项失败与第十批基线集合完全相同，
  无新增失败、无新增错误（其中 9 项为本批新增边界测试）。拆分前后 OpenAPI **排序后字节一致**
  （144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），162 条「方法 + 路径 + 端点函数名」
  与拆分前逐条相同；本批探针路由由 v1 中段的零散位置改为在 v1 末尾随子路由注册（末位注册、无重复），
  经逐条比对，158 个操作的「方法 + 路径」首个命中函数与拆分前完全一致，匹配优先级未变；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 探针域 AST 逐节点比对：11 个移动函数与拆分前完全相同（`heartbeat`、`_latest_ruleset_version`、
  `list_probes`、`delete_probe`、`_probe_removal_target`、`probe_tasks`、`_merge_metadata` 等），
  另 5 处差异全部是本批声明过的改动：`analyze_probe_assets`/`probe_scan` 的 `_dispatch` → `dispatch_task`、
  `probe_metrics` 的 `_aware` → `aware`（导入别名改名）、`register_probe` 与 `crypto_probe_profile` 的
  `raise ... from exc`（B904）。
- 本批修掉拆分造成的 1 项回归：`tests/deployment/test_removal.py` 原先 monkeypatch `v1.dispatch_probe_deployment`，
  改到真实查找位置 `app.api.probes`（与 PCAP 批迁移 monkeypatch 目标同一约定）；该文件 ruff 存量
  仍为 7 项 E501，与拆分前逐项相同。
- 第十批（本机 .venv 隔离全量）671 项：664 passed / 6 failed / 1 skipped；6 项失败与第九批基线集合完全相同，
  无新增失败、无新增错误（其中 7 项为本批新增边界测试）。拆分前后 OpenAPI 排序后字节一致；
  路由仍 162 条记录（158 APIRoute），162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 看板/流量视图域 AST 逐节点比对：13 个移动函数（`risk_summary`、`graph`、`dashboard`、`risk_trend`、
  `dashboard_severity`、`dashboard_engines`、`dashboard_incidents`、`dashboard_high_risk_assets`、
  `dashboard_sensitive_data`、`global_flows`、`global_protocols`、`network_live`、`incident_trend`）
  与拆分前完全相同；长行折行不改 AST。
- `network_live` 里的 `packets` 死赋值是 v1 存量代码（`ruff` F841），本批按原样搬运并加行内
  `# noqa: F841`，不在结构拆分中删除查询或改变行为。
- 第九批（本机 .venv 隔离全量）664 项：657 passed / 6 failed / 1 skipped；6 项失败与第八批基线集合完全相同，
  无新增失败、无新增错误（其中 9 项为本批新增边界测试）。拆分前后 OpenAPI 排序后字节一致；
  路由仍 162 条记录（158 APIRoute），162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 检测/引擎域 AST 逐节点比对：`analysis_results`、`detection_detail`、`engine_registry`、
  `run_engine_pipeline` 与拆分前完全相同，`list_detections` 只差 `_string_time_filter` 改名与改名后的调用；
  `ENGINE_PRESENTATION` 常量值逐节点一致；长行折行与引号规范化不改 AST。
- 第八批（本机 .venv 隔离全量）655 项：648 passed / 6 failed / 1 skipped；6 项失败与第七批基线集合完全相同，
  无新增失败、无新增错误（其中 10 项为本批新增边界测试）。拆分前后 OpenAPI 排序后字节一致；
  路由仍 162 条记录（158 APIRoute），162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同，
  仅注册顺序变化（子路由在 v1 末尾追加，无单段通配路径，匹配结果不变）；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 任务/审计/报表域 AST 逐节点比对：11 个移动函数（`list_tasks`、`create_generic_task`、`task_detail`、
  `stop_task`、`delete_task`、`analyze_log`、`audit`、`generate_report`、`list_reports`、`download_report`、
  `_serialize_report`→`serialize_report`）与拆分前完全相同；长行折行不改 AST。
- 第七批（本机 .venv 隔离全量）645 项：638 passed / 6 failed / 1 skipped；6 项失败与第六批基线集合完全相同，
  无新增失败、无新增错误。拆分前后 OpenAPI 排序后字节一致；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 告警域 AST 逐节点比对：`list_alerts`、`alert_summary`、`alert_stream`、`update_alert` 与拆分前完全相同，
  `alert_detail`、`serialize_probe`、`rule_file_entries`、`rule_definition` 只差改名与改名后的调用。
- 第六批（本机 .venv 隔离全量）637 项：630 passed / 6 failed / 1 skipped；6 项失败与第五批基线集合完全相同，
  无新增失败、无新增错误。拆分前后 OpenAPI 排序后字节一致；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 事件/情报域 AST 逐节点比对：8 个移动函数与拆分前完全相同，唯一差异是 `_string_time_filter`
  改名为 `string_time_filter`；长行折行不改 AST。
- 第五批（本机 .venv 隔离全量）629 项：622 passed / 6 failed / 1 skipped；6 项失败与第四批基线集合完全相同，
  无新增失败、无新增错误。拆分前后 OpenAPI 语义一致（排序后字节一致）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 资产域 AST 逐节点比对：`asset_summary`、`asset_relation_list`、`_incident_touches_asset`、`_finding_touches_asset`
  与拆分前完全相同，其余 6 个移动函数只差 `_serialize_*`/`_aware` 改名与改名后的调用，业务分支未变。
- 第四批（本机 .venv 隔离全量）621 项：614 passed / 6 failed / 1 skipped；6 项失败与第三批基线集合完全相同，
  无新增失败、无新增错误。拆分前后 OpenAPI 字节一致；路由仍 162 条记录（158 APIRoute / 148 路径），
  端点函数名集合一致；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 文件域 AST 逐节点比对：`FILE_TYPE_ALIASES`、`_file_type_candidates`、`file_download` 与拆分前完全相同，
  `serialize_file`（原 `_serialize_file`）、`upload_file`、`list_files`、`file_detail`、`analyze_file` 仅差
  序列化器改名与派发端口调用（`_dispatch` → `dispatch_task_row`），未改动业务分支。
- 第三批（本机 .venv 隔离全量）614 项：607 passed / 6 failed / 1 skipped；6 项失败与第二批基线集合完全相同；
  拆分前后 OpenAPI 字节一致（144 条路径 / 158 个操作）。
- PCAP 行为回归：`tests/test_pcap_workbench.py` 除本机缺少原生导出器 1 项外全部通过。
- 第二批（本机 .venv 隔离全量）608 项：601 passed / 6 failed / 1 skipped。同一提交的干净检出失败 16 项
  （多出的是本机未构建探针分发包导致的 10 项），本批 6 项失败均为其子集，无新增失败。
- 当前 6 项失败与拆分无关：tshark 看门狗与 PCAP 索引上限 2 项、协议引擎夹具 1 项、探针身份注册 1 项、
  PCAP 工作台原生导出 1 项、health 在本机环境判定为 degraded 1 项；尚未修复，也未因本批改变。
- 第一批（容器环境）记录：582 passed / 17 failed，其同环境基线 579 passed / 17 failed，失败集合一致；
  分发包/挂载布局 14 项、缺 Redis/worker 能力 2 项、Zeek 相对 PCAP 路径 1 项。历史数字按当时口径保留。
- 前端本批未改：类型检查、37 项测试、生产构建沿用第一批结论。
- 路由自第一批起保持 162 条记录（158 APIRoute / 148 个路径，其中 144 条在 `/api` 下），十批拆分均未增删路径；无数据库迁移。
- 边界检查累计：`tests/test_task_boundaries.py`（9 项）、`tests/test_data_asset_boundaries.py`（3 项）、
  `tests/test_pcap_boundaries.py`（6 项）、`tests/test_file_boundaries.py`（7 项）、`tests/test_asset_boundaries.py`（8 项）、
  `tests/test_incident_ioc_boundaries.py`（8 项）、`tests/test_alert_boundaries.py`（8 项）、
  `tests/test_tasks_reports_boundaries.py`（10 项）、`tests/test_detection_engine_boundaries.py`（9 项）、
  `tests/test_dashboard_boundaries.py`（7 项）。
- 新增/拆出模块 ruff 与 ruff format 通过；`v1.py` 只减不增（PCAP 批 7 处、文件批 3 处、资产批 2 处、
  告警批 9 处、任务/报表批 6 处、检测/引擎批 7 处、本批 17 处拆分造成的未使用导入），
  其余改动文件的历史 lint 存量未增加。
- 本批没有修改采集判定、风险规则、历史数据或页面布局；没有导入测试数据，未操作真实探针。
- 第二批真实环境只读复验：health 与 8 个只读接口均 200，`/test/status present=false`；资产数是时点采样值
  （`/api/v1/data/assets` 1220、`/api/v1/assets` 214），随真实采集变化，不作验收值。
- 第二批镜像已于 2026-09-20 重建并切换完成：worker 注册 12 个任务名、beat 正常派发、真实队列往返一次成功；
  回退标签 `source-{backend,worker,beat,deployment-worker}:pre-analysis-task-split-20260920`。
- 第三批镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 注册 12 个任务名与上一批一致。
- 第三批真实环境只读复验：16 个只读接口全部 200（含 PCAP 域的列表、详情、协议、异常、提取清单、抓包告警），
  `/test/status present=false`，迁移仍 `0015_alert_hits`（head）；未导入测试数据、未操作真实探针，
  也未写入任务行（不涉及派发，故未做队列往返）。回退标签
  `source-{backend,worker,beat,deployment-worker}:pre-pcap-route-split-20260920`。
- 第四批镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，运行中的 worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 第四批真实环境只读复验：登录后 16 个只读接口全部 200（含文件域列表、详情、下载与 PCAP 域接口），
  `/test/status present=false`，迁移仍 `0015_alert_hits`（head）；未导入测试数据、未操作真实探针。回退标签
  `source-{backend,worker,beat,deployment-worker}:pre-file-route-split-20260920`。
- 第五批镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，运行中的 worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 第五批真实环境只读复验：登录后 18 个只读接口全部 200（含 `/api/v1/assets`、`/assets/summary`、
  `/assets/relations`、`/assets/{id}` 与数据资产、文件域、PCAP 域接口），`/test/status present=false`、
  迁移仍 `0015_alert_hits`（head）；未导入测试数据、未操作真实探针。回退标签
  `source-{backend,worker,beat,deployment-worker}:pre-asset-route-split-20260920`。
- 第六批镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，运行中的 worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 第六批真实环境只读复验：登录后 18 个只读接口全部 200（含 `/incidents`、`/incidents/{id}`、`/iocs`、
  `/iocs/{id}/associations` 与资产、文件、PCAP、数据资产接口。事件 199 条、情报 1 条为时点采样值，
  随真实采集变化，不作验收值），`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  未导入测试数据、未操作真实探针。回退标签
  `source-{backend,worker,beat,deployment-worker}:pre-incident-route-split-20260920`。
- 第七批镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，运行中的 worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 第十批镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，运行中的 worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 第十批真实环境只读复验：登录后 38 个只读接口全部 200（含 `/dashboard/*` 全部卡片、`/risk/summary`、
  `/graph`、`/flows`、`/protocols`、`/network/live`），看板汇总 17 个键、关系图 1834 节点/4426 边、
  协议 24 行且带 layer、`/network/live` 窗口 300 秒；这些均为时点采样值，随真实采集变化，不作验收值。
  `/test/status present=false`、迁移仍 `0015_alert_hits`（head）；未导入测试数据、未操作真实探针。
  回退标签 `source-{backend,worker,beat,deployment-worker}:pre-dashboard-route-split-20260920`。
- 第九批镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，运行中的 worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 第九批真实环境只读复验：登录后 38 个只读接口全部 200（含 `/detections`、`/detections/{id}`、
  `/analysis/results`、`/engine/registry`），检测详情返回 4 个键、引擎清单 15 项且带 UI slug；
  检测 3502 条为时点采样值，随真实采集变化，不作验收值。`/test/status present=false`、
  迁移仍 `0015_alert_hits`（head）；未导入测试数据、未操作真实探针。回退标签
  `source-{backend,worker,beat,deployment-worker}:pre-detection-engine-route-split-20260920`。
- 第八批镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，运行中的 worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 第八批真实环境只读复验：登录后 28 个只读接口全部 200（含 `/tasks`、`/tasks/{id}`、`/audit/summary`、
  `/reports`），`/tasks/{id}` 返回 13 个字段、`/audit/summary` 返回 8 个键；任务 3795 条、报告 2 条为
  时点采样值，随真实采集变化，不作验收值。`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  未导入测试数据、未操作真实探针。回退标签
  `source-{backend,worker,beat,deployment-worker}:pre-task-report-route-split-20260920`。
- 第七批真实环境只读复验：登录后 18 个只读接口全部 200（含 `/alerts`、`/alerts/summary`、`/alerts/{id}`）。
  告警详情返回全部 11 个字段，规则可解析（`matched_snapshot`，标题「端口扫描」），探针字段正常
  （`test123`）；告警 466 条为时点采样值，随真实采集变化，不作验收值。`/test/status present=false`、
  迁移仍 `0015_alert_hits`（head）；未导入测试数据、未操作真实探针。回退标签
  `source-{backend,worker,beat,deployment-worker}:pre-alert-route-split-20260920`。

## 已有系统能力

探针采集/心跳/受控任务；资产、文件与 PCAP 分析；共享敏感识别与扫描预算；数据对象/实例/旧投影；
引擎规则库与命中解释；事件关联与告警；情报适配；报告；探针部署/回收；Vue 控制台与 Docker 部署。
探针只做采集相关工作，服务端承担评分、关联与报告；交付环境只允许真实数据。

## 剩余事项

- 后端路由已全部按域拆出（分析任务编排与 Celery 入口、PCAP 域、文件域、平台资产域、事件/情报域、
  告警域、任务/审计/报表域、检测/引擎域、看板/流量视图域、探针域、集成与离线导入域、规则域，
  以及最后一组 `auth`、`health`、`network_scan`、`test_data`；`v1.py` 自此只做聚合，自身不声明路径）。
  其余待办：前端其余页面（威胁情报/规则页、检测分析、任务与报表、探针页等）按实际改动需求再拆
  （数据安全域、事件/告警中心、资产中心、检测中心、引擎详情、看板、安全审计与流量视图的状态已抽入
  composable）、模型包拆分，最后是探针模块与分发包。
- 历史对象计数/投影/告警命中回填仍是独立任务；只读 remediation_dry_run 工具已存在，不能默认执行修复。
- 旧测试布局与既有失败需单独解决，不在结构移动中绕过测试。
- 旧代码 ruff 存量仍存在；仅约束本次新增/变更内容，不全仓格式化。
- 旧门面（`workers/tasks.py`、`data_object_service.py`）在确无调用方后再删除。

本批不变更外部 API、数据库定义、Celery 任务名、任务协议和真实探针版本；旧 Python 入口暂保留兼容导出。
