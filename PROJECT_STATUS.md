# 项目状态

更新时间：2026-09-20。当前任务见 TASK.md；稳定约束见 AGENTS.md；模块关系见 docs/architecture.md。
历史时点数字与旧问题讨论已移至 [本批前完整状态](docs/history/project_status-before-data-asset-refactor-2026-09-19.md)。

## 版本与工作分支

| 项目 | 当前值 |
| --- | --- |
| 最近发布 | Git 注释标签 v2.12.0，发布提交 d1c1569 |
| 源码内平台版本 | 2.11.0（上一轮按不改代码约定保留，本轮不发新版本） |
| 探针源码版本 | 3.5.0；本轮未改探针或分发包 |
| 本批基线 / 分支 | e8994a9 / refactor/data-asset-boundaries |
| 数据库迁移 | 0015_alert_hits；本批无模型/表结构变更 |
| 本批范围 | 第六批：事件与情报域路由拆分；前五批（数据资产边界、分析编排与 Celery 入口、PCAP 域、文件域、平台资产域）见下方记录 |

## 本批已落地结构

- 事件与情报域路由独立为 `api/incidents.py`（7 条路径：事件列表/详情/状态更新/关联计算/归属重建、
  情报列表/关联），关联计算仍在 `incident_engine`、归属重建仍在 `incident_engine.attribution`，
  路由只做鉴权、分页与响应结构；由 `v1.router` 只 include 一次，前缀只叠加一次。
- 列表时间过滤下沉为 `api/query_filters.py::string_time_filter`（原 v1 私有 `_string_time_filter`），
  事件域与其他列表域共用一份实现；行序列化继续复用已下沉的检测/事件/IOC/资产 presenter，不新增副本。
- 第五批边界维持：平台资产域路由在 `api/assets.py`（4 条路径）并导出 `serialize_asset`，
  事件/IOC 行序列化在 `api/incident_presenter.py`、`api/ioc_presenter.py`，
  时间归一化在 `core/datetimes.py::aware`。
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
| backend/app/api/v1.py | 2557 | 1674 |
| backend/app/api/incidents.py | 0（本批新增） | 162 |
| backend/app/api/query_filters.py | 0（本批新增） | 11 |
| backend/app/api/assets.py | 0（第五批新增） | 238 |
| backend/app/api/incident_presenter.py | 0（第五批新增） | 55 |
| backend/app/api/ioc_presenter.py | 0（第五批新增） | 22 |
| backend/app/core/datetimes.py | 0（第五批新增） | 25 |
| backend/app/api/files.py | 0（第四批新增） | 206 |
| backend/app/api/pcaps.py | 0（第三批新增） | 649 |
| backend/app/api/task_presenter.py | 0（第三批新增） | 25 |
| backend/app/api/dependencies.py | 12 | 49 |
| backend/app/api/extensions.py | 718 | 364 |
| backend/app/services/data_object_service.py | 1165 | 58（兼容导出） |
| backend/app/workers/tasks.py | 981 | 43（兼容门面） |
| backend/app/incident_engine/engine.py | 344 | 263（身份解析移出） |
| frontend/src/modules/data-security/DataAsset.vue | 285 | 144 |

逻辑被移动到有明确职责的模块，不是删除功能；不得用总行数变化代替维护效率评估。

## 验证与已知限制

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
- 路由自第一批起保持 162 条记录（158 APIRoute / 148 个路径，其中 144 条在 `/api` 下），六批拆分均未增删路径；无数据库迁移。
- 边界检查累计：`tests/test_task_boundaries.py`（9 项）、`tests/test_data_asset_boundaries.py`（3 项）、
  `tests/test_pcap_boundaries.py`（6 项）、`tests/test_file_boundaries.py`（7 项）、`tests/test_asset_boundaries.py`（8 项）、
  `tests/test_incident_ioc_boundaries.py`（8 项）。
- 新增/拆出模块 ruff 与 ruff format 通过；`v1.py` 只减不增（PCAP 批 7 处、文件批 3 处、本批 2 处拆分造成的未使用导入），
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

## 已有系统能力

探针采集/心跳/受控任务；资产、文件与 PCAP 分析；共享敏感识别与扫描预算；数据对象/实例/旧投影；
引擎规则库与命中解释；事件关联与告警；情报适配；报告；探针部署/回收；Vue 控制台与 Docker 部署。
探针只做采集相关工作，服务端承担评分、关联与报告；交付环境只允许真实数据。

## 剩余事项

- 其余大路由、其他前端页面、模型包和探针尚按总体指南待拆分（已完成：分析任务编排与 Celery 入口、
  PCAP 域、文件域、平台资产域、事件/情报域路由；待拆：告警、任务/审计/报告、检测/引擎、Dashboard、探针域）。
- 历史对象计数/投影/告警命中回填仍是独立任务；只读 remediation_dry_run 工具已存在，不能默认执行修复。
- 旧测试布局与既有失败需单独解决，不在结构移动中绕过测试。
- 旧代码 ruff 存量仍存在；仅约束本次新增/变更内容，不全仓格式化。
- 旧门面（`workers/tasks.py`、`data_object_service.py`）在确无调用方后再删除。

本批不变更外部 API、数据库定义、Celery 任务名、任务协议和真实探针版本；旧 Python 入口暂保留兼容导出。
