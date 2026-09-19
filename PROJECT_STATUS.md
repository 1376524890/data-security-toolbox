# 项目状态

更新时间：2026-09-20。当前任务见 TASK.md；稳定约束见 AGENTS.md；模块关系见 docs/architecture.md。
历史时点数字与旧问题讨论已移至 [本批前完整状态](docs/history/project_status-before-data-asset-refactor-2026-09-19.md)。

## 版本与工作分支

| 项目 | 当前值 |
| --- | --- |
| 最近发布 | Git 注释标签 v2.12.0，发布提交 d1c1569 |
| 源码内平台版本 | 2.11.0（上一轮按不改代码约定保留，本轮不发新版本） |
| 探针源码版本 | 3.5.0；本轮未改探针或分发包 |
| 本批基线 / 分支 | 052ac15 / refactor/data-asset-boundaries |
| 数据库迁移 | 0015_alert_hits；本批无模型/表结构变更 |
| 本批范围 | 第十三批：规则域路由拆分；前十二批（数据资产边界、分析编排与 Celery 入口、PCAP 域、文件域、平台资产域、事件/情报域、告警域、任务/审计/报表域、检测/引擎域、看板/流量视图域、探针域、集成与离线导入域）见下方记录 |

## 本批已落地结构

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

- 其余大路由、其他前端页面、模型包和探针尚按总体指南待拆分（已完成：分析任务编排与 Celery 入口、
  PCAP 域、文件域、平台资产域、事件/情报域、告警域、任务/审计/报表域、检测/引擎域、看板/流量视图域、
  探针域、集成与离线导入域、规则域路由；
  待收敛：`auth`、`health`、`scan`、`test` 等仍留在 `v1.py` 的零散入口）。
- 历史对象计数/投影/告警命中回填仍是独立任务；只读 remediation_dry_run 工具已存在，不能默认执行修复。
- 旧测试布局与既有失败需单独解决，不在结构移动中绕过测试。
- 旧代码 ruff 存量仍存在；仅约束本次新增/变更内容，不全仓格式化。
- 旧门面（`workers/tasks.py`、`data_object_service.py`）在确无调用方后再删除。

本批不变更外部 API、数据库定义、Celery 任务名、任务协议和真实探针版本；旧 Python 入口暂保留兼容导出。
