# 当前任务：分批解耦（数据资产采集与展示优先）

## 用户需求与约定

- 用户提出业务需求，AI 负责后续代码修改；优先让数据资产采集方式与展示方式更易维护。
- 按批次持续推进后端与前端解耦，探针放在最后；本机服务允许短暂停机更新。
- 每批保持现有行为/API/数据库/探针协议兼容，以隔离回归和真实环境只读检查验收。
- 禁止导入测试数据、生产 mock；未授权操作真实探针主机。

## 第一批：数据资产边界（2026-09-19）

基线 `5c5b1d4`，分支 `refactor/data-asset-boundaries`。

已完成代码：

- 公共鉴权移至 `api/dependencies.py`；采集建任务移至 `services/probe_task_service.py`；
  服务领域异常在 `api/error_handlers.py` 转为原有 404/409。提交时点和任务快照不变。
- 采集协议 `api/data_collection_schemas.py`、采集接口 `api/data_collection.py`、
  旧资产页与敏感发现接口 `api/data_assets.py` 从大路由独立；旧入口保留兼容导出。
- 数据对象服务拆为 `services/data_objects/{definitions,values,identity,coverage,persistence,evidence,ingestion,projection,queries,progress}.py`；
  旧 `data_object_service.py` 仅为 58 行兼容导出，新生产调用使用具体模块。
- 前端 `DataAsset.vue` 从 285 行缩至 144 行；列表/详情与采集任务状态分别由两个 composable 管理，模板不变。
- 增加 3 项后端依赖边界检查、3 项前端行为回归；明确禁止循环依赖与服务反向导入 API/worker。
- 新增 [数据资产开发入口](docs/数据资产开发入口.md)，压缩当前上下文，旧记录完整归档。

验证：

- 同环境后端基线 579 passed / 17 failed；本批 582 passed / 17 failed，失败集合一致。
- 前端 typecheck、37 项单测、生产构建通过；新增/拆出的后端模块 ruff 通过。
- 拆分前后 OpenAPI、162 个路由记录、38 张表的列/索引定义完全一致；没有新增迁移。
- Python 模块语法检查、git diff --check 通过。全量回归中发现并修正的遗漏 `re` 导入已验证。
- 切换前真实环境 8 个只读 API 均 200，`/test/status present=false`；资产数 1087（时点值，不是固定验收值）。

已完成：应用镜像于 2026-09-19 重建并切换本机服务（backend/worker/beat/deployment-worker/frontend 正常）；
切换后复验 8 个只读接口均 200、`/test/status present=false`、迁移仍为 `0015_alert_hits`（head）。
回退标签 `source-{backend,worker,frontend}:pre-data-asset-refactor-20260919` 可用。第一批含切换收尾完成。

## 第二批：分析编排与 Celery 任务入口（2026-09-20）

基线 `f60dd11`，同一分支。目标：分析编排离开 Celery 任务文件，API 不再导入 worker 私有函数与任务对象。

已完成代码：

- 证据身份解析（资产 / IOC）移至 `domain/evidence_identity.py`（纯逻辑、不查库）；
  `incident_engine/engine.py` 只兼容重导出 `evidence_asset_keys`、`evidence_ioc_keys`、
  `evidence_primary_asset`、`_short_asset`、`_asset_identity` 等旧名字，语义不变。
- 跨域分析编排移至 `application/analysis.py`：`run_pipeline`、`recent_findings`、`merge_findings`、
  `upsert_incident`、`run_correlations_and_alerts`、`capture_exposure`。事务边界不变（仅自建 session 才 commit）。
- 任务行持久化移至 `services/task_service.py`（`create_task` / `update_task`）；派发端口为
  `services/task_dispatch.py`：按注册名派发，broker 不可用时回退本进程；`enqueue` 无内联回退，供需要 503 的路径使用。
- worker 按职责拆分：`workers/analysis_tasks.py`、`notification_tasks.py`、`maintenance_tasks.py`；
  任务生命周期在 `workers/task_runtime.py`，任务名集中在 `workers/task_names.py`（名字与参数顺序均未改）。
- 旧 `workers/tasks.py` 成为 43 行兼容门面且不再有任务装饰器；`celery_app.py` 的 include 指向新模块。
- API 不再导入 `app.workers.*`：`api/v1.py` 改为 `_dispatch(task_id, 注册名, ...)`，健康检查用 `queue_depth()`；
  `api/extensions.py` 用 `enqueue`；`api/deployments.py`、`services/test_service.py` 同样走端口。
- 新增 `tests/test_task_boundaries.py`（9 项）：端口独占 worker 依赖、路由不含任务对象/私有名、
  应用层不依赖 HTTP 与 worker、门面仍导出旧名字、门面无重复注册、beat/route 名字均已注册、派发参数顺序与回退行为。

验证：

- 本机隔离全量 608 项：601 passed / 6 failed / 1 skipped；同一提交的干净检出失败 16 项（含本机未构建探针包的 10 项），
  本批 6 项失败全部是该集合的子集，无新增失败、无新增错误。
- 路由仍为 162 条记录（158 APIRoute / 144 路径）；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 新增/拆出模块 ruff 与 ruff format 通过；`v1.py`、`extensions.py`、`deployments.py`、`test_service.py`
  改动前后 ruff 统计逐项一致（历史存量不因本批增加）。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker：worker 注册 12 个任务名，
  beat 正常派发，无 unregistered task；经真实队列往返一次 `worker_capability_heartbeat` 成功。
- 真实环境只读复验：health 与 8 个只读接口均 200，`/test/status present=false`；未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-analysis-task-split-20260920`。

## 第三批：PCAP 域路由拆分（2026-09-20）

基线 `9833cad`，同一分支。目标：按指南 §C 把 PCAP 域路由从 `api/v1.py` 独立，路径/方法/鉴权/分页不变；
对应第二批清单第 2 项（继续拆其他大路由）的首个域。

已完成代码：

- PCAP 路由与专用序列化移至 `api/pcaps.py`：上传、列表/详情/分析、包/流、协议/流量、DNS/HTTP/TLS、
  提取清单/预览/下载、抓包告警共 18 条路径；`v1.router` 以 `include_router(pcaps_router)` 只注册一次，
  `/api/v1` 前缀只叠加一次。
- 上传归属与队列背压从 v1 私有函数移至 `api/dependencies.py`（`upload_probe_id`、
  `enforce_queue_backpressure`），语义不变（鉴权失败仍按原错误码抛出，队列拥挤仍是 429 + `Retry-After`）；
  文件上传路由继续复用同一份实现。
- Task 行序列化提取为 `api/task_presenter.py::serialize_task`，PCAP 域与 tasks 路由共用一份，不再复制。
- 文件末尾的兼容下载端点（`packets/{id}`、`streams/{id}`、`files/{id}/download`）随域整体移动，不是按连续行区间剪切。
  v1 保留 `_dispatch`（文件/探针域仍在用），PCAP 域直接经 `task_dispatch.dispatch_task_row` 派发，参数顺序不变。
- 新增 `tests/test_pcap_boundaries.py`（6 项）：18 条路径/方法冻结、仅由 `api/pcaps.py` 声明、仍挂在 `/api/v1` 下、
  全应用无重复「方法 + 路径」、PCAP 域不导入 workers/extensions、上传守卫位于共享依赖模块、v1 只聚合一次。
- 测试 monkeypatch 目标迁到真实位置：`tests/test_pcap_workbench.py` 改为 patch
  `pcaps.dispatch_task_row` 与 `pcaps.enforce_queue_backpressure`。

验证：

- 本机 .venv 隔离全量 614 项：607 passed / 6 failed / 1 skipped；6 项失败与第二批基线集合完全相同，无新增失败、无新增错误。
- 拆分前后 OpenAPI **字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute / 148 路径），
  端点函数名集合一致；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- `tests/test_pcap_workbench.py` 除本机缺少原生导出器 1 项外全部通过：重复上传仍返回原 ID、
  提取文件下载仍按抓包清单校验、缺包/越界/非法哈希仍为 404/422。
- 新增/拆出文件（`api/pcaps.py`、`api/task_presenter.py`、`tests/test_pcap_boundaries.py`）ruff check 与 ruff format 通过；
  `v1.py` 只减不增，另清理了拆分造成的 7 处未使用导入，历史存量（E501/B008/B904/F841）不变。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 注册 12 个任务名与第二批一致。
- 真实环境只读复验：登录后 16 个只读接口全部 200（含 PCAP 域的列表、详情、协议、异常、提取清单、抓包告警），
  `/test/status present=false`；迁移仍 `0015_alert_hits`（head）。本批未导入测试数据、未操作真实探针，
  也未写入任务行（不涉及派发，故未做队列往返）。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-pcap-route-split-20260920`。

## 第四批：文件域路由拆分（2026-09-20）

基线 `22fc303`，同一分支。目标：按指南 §C 把文件证据域路由从 `api/v1.py` 独立，路径/方法/鉴权/分页不变；
对应后续批次第 1 项（继续按域拆其余 v1 路由）的第二个域。

已完成代码：

- 文件路由与专用序列化移至 `api/files.py`：`POST /files/upload`、`GET /files`、`GET /files/{file_id}`、
  `GET /files/{file_id}/download`、`POST /files/{file_id}/analyze` 共 5 条路径，连同扩展名/MIME 过滤器
  （`FILE_TYPE_ALIASES`、`_file_type_candidates`）；原 `_serialize_file` 改名导出为 `serialize_file`。
- 共享边界不复制：上传归属复用 `api/dependencies.py::upload_probe_id`，Task 行序列化复用
  `api/task_presenter.py::serialize_task`，派发直接走 `services/task_dispatch.dispatch_task_row`；
  文件哈希与元数据仍在 `services/metadata_service.py`，检测仍在 worker。
- `v1.router` 以 `include_router(files_router)` 只注册一次，`/api/v1` 前缀只叠加一次；v1 内对
  `serialize_file` 的调用改为从新模块导入，不保留重复实现。
- 新增 `tests/test_file_boundaries.py`（7 项）：5 条路径/方法冻结、仅由 `api/files.py` 声明、仍挂 `/api/v1` 下、
  全应用无重复「方法 + 路径」、文件域不导入 workers/extensions、不复制共享守卫、v1 只聚合一次。
- 上一批 PCAP 边界测试里「v1 必须直接导入某共享符号」的断言改为按域模块检查，避免后续域拆分误伤。

验证：

- 本机 .venv 隔离全量 621 项：614 passed / 6 failed / 1 skipped；6 项失败与第三批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute / 148 路径），
  端点函数名集合一致；移动符号的 AST 逐节点比对只差序列化器改名与派发端口调用；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 新增/拆出文件（`api/files.py`、`tests/test_file_boundaries.py`）ruff check 与 ruff format 通过；
  `v1.py` 2121 → 1985 行，只减不增，另清理了拆分造成的 3 处未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 注册任务名与上一批一致。
- 真实环境只读复验：登录后 16 个只读接口全部 200（含文件域列表/详情/下载与 PCAP 域接口），
  `/test/status present=false`、迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-file-route-split-20260920`。

## 第五批：平台资产域路由拆分（2026-09-20）

基线 `ee18eef`，同一分支。目标：按指南 §C 把平台资产（主机资产）域路由从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的第三个域。

已完成代码：

- 资产路由与资产行序列化移至 `api/assets.py`：`GET /assets`、`GET /assets/summary`、`GET /assets/relations`、
  `GET /assets/{asset_id}` 共 4 条路径，连同 `_incident_touches_asset`、`_finding_touches_asset` 两个
  「证据是否命中本资产」判定；原 `_serialize_asset` 改名导出为 `serialize_asset`（其余 6 处 v1 调用点改为导入）。
- 资产详情同时返回检测、事件、IOC 行，因此把跨域复用的行序列化下沉为 `api/incident_presenter.py`
  （`serialize_incident`）与 `api/ioc_presenter.py`（`serialize_ioc`），v1 与资产域共用一份，不复制。
- 三个序列化器共用的时间归一化函数独立为 `core/datetimes.py::aware`（原 v1 私有 `_aware`），
  v1 以 `aware as _aware` 复用，保留原有 tz-aware 输出语义。
- `v1.router` 以 `include_router(assets_router)` 只注册一次，`/api/v1` 前缀只叠加一次；数据资产（`data/assets`）
  与平台资产的边界保持不变，`/data/assets` 仍属 `api/data_assets.py`。
- 新增 `tests/test_asset_boundaries.py`（8 项）：4 条路径/方法冻结、仅由 `api/assets.py` 声明、仍挂 `/api/v1` 下、
  全应用无重复「方法 + 路径」、资产域不导入 workers/extensions、复用而非复制共享序列化器、
  `_aware`/`_serialize_*` 不再回到 v1、时间归一化只有一份实现、v1 只聚合一次。

验证：

- 本机 .venv 隔离全量 629 项：622 passed / 6 failed / 1 skipped；6 项失败与第四批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **语义与排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录
  （158 APIRoute / 144 个 API 路径），162 条「方法 + 路径 + 端点名」与拆分前逐条相同，无新增/丢失；
  AST 逐节点比对显示移动的 10 个函数只差 `_serialize_*`/`_aware` 改名与改名后的调用；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 长行按既有模块标准折行（与 PCAP/文件域一致），新增/拆出 5 个文件 ruff check 与 ruff format 通过；
  `v1.py` 1985 → 1763 行，只减不增，另清理了拆分造成的 2 处未使用导入（`String`、`cast`）。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 18 个只读接口全部 200（含 `/api/v1/assets`、`/assets/summary`、`/assets/relations`、
  `/assets/{id}` 与文件域、PCAP 域、数据资产接口），`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-asset-route-split-20260920`。

## 第六批：事件与情报域路由拆分（2026-09-20）

基线 `e8994a9`，同一分支。目标：按指南 §C 把事件（incidents）与情报（iocs）域路由从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的第四个域。

已完成代码：

- 事件与情报路由移至 `api/incidents.py`：`GET /incidents`、`GET /incidents/{incident_id}`、
  `PATCH /incidents/{incident_id}`、`POST /incidents/correlate`、`POST /incidents/rebuild-attribution`、
  `GET /iocs`、`GET /iocs/{ioc_id}/associations` 共 7 条路径；关联计算仍在 `incident_engine`
  （路由只调用 `IncidentEngine().correlate`），归属重建仍在 `incident_engine.attribution`。
- 列表时间过滤（原 v1 私有 `_string_time_filter`）下沉为 `api/query_filters.py::string_time_filter`，
  供事件域与其他列表域共用；v1 以别名导入，检测列表调用点不变。
- 行序列化继续复用第五批已下沉的 presenter（检测/事件/IOC/资产），本批不新增序列化副本。
- `v1.router` 以 `include_router(incidents_router)` 只注册一次，`/api/v1` 前缀只叠加一次。
- 新增 `tests/test_incident_ioc_boundaries.py`（8 项）：7 条路径/方法冻结、仅由 `api/incidents.py` 声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、事件域不导入 workers/extensions、
  复用而非复制共享 presenter、关联计算未在路由里重写、时间过滤只有一份实现、v1 只聚合一次。

验证：

- 本机 .venv 隔离全量 637 项：630 passed / 6 failed / 1 skipped；6 项失败与第五批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同；8 个移动函数的 AST 与拆分前逐节点完全一致
  （唯一的差异是过滤函数改名）；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 新增/拆出文件 ruff check 与 ruff format 通过（长行按既有模块标准折行）；`v1.py` 1763 → 1674 行，
  只减不增，无因拆分产生的未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 18 个只读接口全部 200（含 `/incidents`、`/incidents/{id}`、`/iocs`、
  `/iocs/{id}/associations` 与资产、文件、PCAP、数据资产接口），`/test/status present=false`、
  迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-incident-route-split-20260920`。

## 第七批：告警域路由拆分（2026-09-20）

基线 `74118db`，同一分支。目标：按指南 §C 把告警域路由从 `api/v1.py` 独立，路径/方法/鉴权/分页与
响应结构不变；对应后续批次第 1 项的第五个域。

已完成代码：

- 告警路由移至 `api/alerts.py`：`GET /alerts`、`GET /alerts/summary`、`GET /alerts/stream`（SSE）、
  `GET /alerts/{alert_id}`、`PATCH /alerts/{alert_id}` 共 5 条路径；抑制合并、命中聚合与投递仍由
  `services/alert_service.py` 负责，路由只做鉴权、筛选与响应组装。
- 告警详情依赖探针行与规则定义，因此跨域复用部分下沉为 `api/probe_presenter.py::serialize_probe`
  与 `api/rule_presenter.py::rule_definition`/`rule_file_entries`（原 v1 私有 `_serialize_probe`、
  `_rule_definition`、`_rule_file_entries`）；`/rules` 路由改为导入共享 `rule_file_entries`，
  测试 monkeypatch/导入目标同步迁到 `app.api.rule_presenter`，不保留 v1 重复实现。
- 行序列化继续复用既有 presenter（检测/事件/IOC/资产/数据资产/PCAP），本批不新增序列化副本。
- `v1.router` 以 `include_router(alerts_router)` 只注册一次，`/api/v1` 前缀只叠加一次。
- 新增 `tests/test_alert_boundaries.py`（8 项）：5 条路径/方法冻结、仅由 `api/alerts.py` 声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、告警域不导入 workers/extensions、
  复用而非复制共享 presenter、抑制/投递未在路由里重写、探针与规则查询未回到 v1、v1 只聚合一次。

验证：

- 本机 .venv 隔离全量 645 项：638 passed / 6 failed / 1 skipped；6 项失败与第六批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同；8 个移动函数的 AST 与拆分前逐节点一致
  （唯一差异是 `_serialize_probe`/`_rule_*` 改名与改名后的调用）；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 新增/拆出 4 个模块 ruff check 与 ruff format 通过；`v1.py` 1674 → 1320 行，只减不增，
  另清理了拆分造成的 9 处未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 18 个只读接口全部 200（含 `/alerts`、`/alerts/summary`、`/alerts/{id}`），
  告警详情返回全部 11 个字段，规则快照可解析（`matched_snapshot`，标题「端口扫描」）、探针字段正常；
  `/test/status present=false`、迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-alert-route-split-20260920`。

## 第八批：任务/审计/报表域路由拆分（2026-09-20）

基线 `d5e7f73`，同一分支。目标：按指南 §C 把任务队列、审计与报表路由从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的下一个域（指南中记为 tasks/audit/reports）。

已完成代码：

- 任务路由移至 `api/tasks.py`：`GET /tasks`、`POST /tasks`、`GET /tasks/{task_id}`、
  `POST /tasks/{task_id}/stop`、`DELETE /tasks/{task_id}` 共 5 条路径；行创建仍走
  `services/task_service.py::create_task`、过期仍走 `services/probe_task_service.py`
  （`expire_probe_tasks`、`visible_tasks`），停止/删除的 `PROBE_TASK_KINDS`、`TERMINAL` 判定随域移动。
- 审计与报表路由移至 `api/reports.py`：`POST /audit/logs`、`GET /audit/summary`、
  `POST /reports/generate`、`GET /reports`、`GET /reports/{report_id}/download` 共 5 条路径；
  汇总/日志分析仍在 `services/audit_service.py`、报告构建/渲染仍在 `services/report_service.py`。
- 报告行序列化 `_serialize_report` 随域下沉为 `api/reports.py::serialize_report`，v1 不再保留副本；
  资产/文件/PCAP/检测/事件/数据资产行继续复用既有 presenter，本批不新增序列化副本。
- `v1.router` 以 `include_router(tasks_router)`、`include_router(reports_router)` 各只注册一次。
- 新增 `tests/test_tasks_reports_boundaries.py`（10 项）：两组路径/方法冻结、仅由对应模块声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、两域均不导入 workers/extensions、
  Task 行与共享 presenter 复用而未复制、任务/报表逻辑仍在 service、`serialize_report` 未复制回 v1、
  v1 各只聚合一次。

验证：

- 本机 .venv 隔离全量 655 项：648 passed / 6 failed / 1 skipped；6 项失败与第七批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同，仅注册顺序变化（子路由在 v1 末尾追加；
  全应用无单段通配路径，匹配结果不变）；11 个移动函数的 AST 与拆分前逐节点一致（唯一差异是
  `_serialize_report`→`serialize_report` 改名与改名后的调用，长行折行不改 AST）；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 新增/拆出 3 个模块 ruff check 与 ruff format 通过；`v1.py` 1320 → 1176 行，只减不增，
  另清理了拆分造成的 6 处未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 28 个只读接口全部 200（含 `/tasks`、`/tasks/{id}`、`/audit/summary`、`/reports`），
  任务详情返回 13 个字段、审计汇总返回 8 个键；任务 3795 条、报告 2 条为时点采样值，随真实采集变化；
  `/test/status present=false`、迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-task-report-route-split-20260920`。

## 第九批：检测/引擎域路由拆分（2026-09-20）

基线 `6e19403`，同一分支。目标：按指南 §C 把检测结果与引擎目录路由从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的下一个域（指南中记为 detections/engine）。

已完成代码：

- 检测结果路由移至 `api/detections.py`：`GET /detections`、`GET /detections/{detection_id}`、
  `GET /analysis/results` 共 3 条路径；行序列化继续复用 finding/事件/PCAP/告警 presenter，
  列表时间过滤改用共享 `api/query_filters.py::string_time_filter`（原 v1 `_string_time_filter` 别名）。
- 引擎路由移至 `api/engines.py`：`GET /engine/registry`、`POST /engine/pipeline` 共 2 条路径；
  引擎清单读 `app.engine.registry`、规则清单走 `api/rule_presenter.py::rule_file_entries`，
  内部引擎名到 UI slug 的映射 `ENGINE_PRESENTATION`（原 v1 模块常量）随域移动，v1 不再保留。
- 检测判定仍在 `app/engine/*`，本批未改任何引擎、规则或评分逻辑。
- `v1.router` 以 `include_router(detections_router)`、`include_router(engines_router)` 各只注册一次。
- 新增 `tests/test_detection_engine_boundaries.py`（9 项）：两组路径/方法冻结、仅由对应模块声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、两域均不导入 workers/extensions、
  检测域复用而未复制共享 presenter 与时间过滤、引擎域读真实 registry 与规则清单、
  `ENGINE_PRESENTATION` 未复制回 v1、v1 各只聚合一次。

验证：

- 本机 .venv 隔离全量 664 项：657 passed / 6 failed / 1 skipped；6 项失败与第八批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同；`analysis_results`、`detection_detail`、
  `engine_registry`、`run_engine_pipeline` 的 AST 与拆分前逐节点一致，`list_detections` 只差
  `_string_time_filter` 改名与改名后的调用，`ENGINE_PRESENTATION` 常量值一致；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 新增/拆出 3 个模块 ruff check 与 ruff format 通过；`v1.py` 1176 → 1055 行，只减不增，
  另清理了拆分造成的 7 处未使用导入。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 38 个只读接口全部 200（含 `/detections`、`/detections/{id}`、
  `/analysis/results`、`/engine/registry`），检测详情返回 4 个键、引擎清单 15 项且带 UI slug；
  检测 3502 条为时点采样值，随真实采集变化；`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-detection-engine-route-split-20260920`。

## 第十批：看板/流量视图域路由拆分（2026-09-20）

基线 `25cbbd5`，同一分支。目标：按指南 §C 把看板、风险总览、关系图与全局流量视图从 `api/v1.py` 独立，
路径/方法/鉴权/分页与响应结构不变；对应后续批次第 1 项的下一个域（指南中记为 dashboard）。

已完成代码：

- 看板与流量视图移至 `api/dashboard.py`（13 条路径）：`GET /risk/summary`、`GET /graph`、
  `GET /dashboard/summary|risk-trend|severity|engines|incidents|high-risk-assets|sensitive-data|incident-trend`、
  `GET /flows`、`GET /protocols`、`GET /network/live`。
- 所有数字仍由 `app/models.py` 的行实时聚合，未新增缓存、派生表或写死常量；行序列化继续复用
  资产/事件/流量/探针 presenter，协议分层复用 `services/protocol_service.py::protocol_layer`，
  分页复用 `api/pagination.py`，本批不新增序列化副本。
- `network_live` 内的 `packets` 死赋值是 v1 存量（`ruff` F841），按原样搬运并加行内 `# noqa: F841`，
  不在结构拆分中删除查询或改变行为。
- `v1.router` 以 `include_router(dashboard_router)` 只注册一次。
- 新增 `tests/test_dashboard_boundaries.py`（7 项）：13 条路径/方法冻结、仅由 `api/dashboard.py` 声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、域不导入 workers/extensions、
  复用而非复制共享 presenter 与协议分层、聚合结果来自模型行、v1 只聚合一次。

验证：

- 本机 .venv 隔离全量 671 项：664 passed / 6 failed / 1 skipped；6 项失败与第九批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute），
  162 条「方法 + 路径 + 端点名」与拆分前逐条相同；13 个移动函数的 AST 与拆分前逐节点一致；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 新增/拆出 2 个模块 ruff check 与 ruff format 通过；`v1.py` 1055 → 804 行，只减不增，
  另清理了拆分造成的 17 处未使用导入（`v1.py` 因此第一次达到 `ruff check --select F` 全通过，
  仅余的存量 F841 已随 `network_live` 迁到本域并用行内 noqa 标注）。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 38 个只读接口全部 200（含看板全部卡片、`/risk/summary`、`/graph`、`/flows`、
  `/protocols`、`/network/live`），看板汇总 17 个键、关系图 1834 节点/4426 边、协议 24 行且带 layer、
  `/network/live` 窗口 300 秒；这些为时点采样值，随真实采集变化；`/test/status present=false`、
  迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-dashboard-route-split-20260920`。

## 第十一批：探针域路由拆分（2026-09-20）

基线 `c2dc28b`，同一分支。目标：按指南 §C 把探针域路由从 `api/v1.py` 独立，路径/方法/鉴权/分页不变；
对应后续批次第 1 项的下一个域（指南中记为 probes），也是探针模块化之前的最后一块探针相关 HTTP 边界。

已完成代码：

- 探针注册、心跳、列表、删除、分析、任务、扫描、指标与加密画像移至 `api/probes.py`（9 条路径）：
  `POST /probes/register`、`POST /probes/{probe_id}/heartbeat`、`GET /probes`、`DELETE /probes/{probe_id}`、
  `POST /probes/{probe_id}/analyze`、`GET /probes/{probe_id}/tasks`、`POST /probes/{probe_id}/scan`、
  `GET /probes/{probe_id}/metrics`、`GET /crypto/probe-profile`，连同本域私有辅助
  `_merge_metadata`、`_latest_ruleset_version`、`_probe_removal_target` 一并随域下沉。
- 共享边界不复制：探针鉴权仍在 `core/security.py` 与 `api/dependencies.py`，登记入册仍在
  `deployment/enrollment.py`，删除记录与远端卸载仍在 `services/probe_service.py`、`deployment/removal.py`，
  任务行仍在 `services/task_service.py`，行序列化复用 `api/probe_presenter.py::serialize_probe` 与
  `api/task_presenter.py::serialize_task`；探针下发/回收、规则下发、扫描任务与采集上报仍分属
  `api/deployments.py`、`api/rulesets.py`、`api/extensions.py`、`api/data_collection.py`。
- 本域原先在 v1 内使用的私有派发 `_dispatch(task_id, 注册名, ...)` 下沉为共享
  `api/dependencies.py::dispatch_task`（docstring 原样保留、参数顺序与回退语义不变），v1 删除该本地定义。
- 随域移动的两处 `raise HTTPException(...)` 按 ruff B904 补 `from exc`（异常类型与状态码不变，
  是纯 lint 修复，不是行为改动）；`v1.py` ruff 存量由 68 项（37 E501 / 29 B008 / 2 B904）降为 46 项
  （27 E501 / 19 B008），只减不增。
- 新增 `tests/test_probe_boundaries.py`（9 项）：9 条路径/方法冻结、仅由 `api/probes.py` 声明、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、域不导入 workers/extensions、不复制共享守卫、
  派发走共享端口、v1 只聚合一次。
- 拆分造成的 1 项测试回归已修：`tests/deployment/test_removal.py` 的 monkeypatch 目标从
  `v1.dispatch_probe_deployment` 迁到真实查找位置 `app.api.probes`（PCAP 批同一约定）；
  `tests/test_ruleset_release.py` 的 `_latest_ruleset_version` 导入改到 `app.api.probes`。

验证：

- 本机 .venv 隔离全量 680 项：673 passed / 6 failed / 1 skipped；6 项失败与第十批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute）、
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；探针路由由 v1 中段零散位置改为随子路由在末尾注册，
  逐条比对 158 个操作的「方法 + 路径」首个命中函数与拆分前完全一致（匹配优先级未变）；无数据库变更，
  迁移仍 `0015_alert_hits`（head）。
- 11 个移动函数的 AST 与拆分前逐节点一致；另 5 处差异均为本批声明过的改名/`from exc`（见上）。
- 新增/拆出文件 ruff check 与 ruff format 通过；`v1.py` 只减不增且 `--select F` 全通过。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy、日志无 Traceback/ERROR/unregistered，worker 仍注册 12 个 `security_toolbox.*` 任务名。
- 真实环境只读复验：登录后 38 个只读接口 + 本域 3 个明细接口（`/probes/{id}/tasks`、`/probes/{id}/metrics`、
  `/crypto/probe-profile?probe_id=`）共 41 项全部 200；探针 1 台（`test123`）、指标 15 个键、
  任务行 9 条、加密画像 11 个键；`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  本批未导入测试数据、未对真实探针主机做任何写操作（仅 GET 读取）。
- 真实环境资产/图/流量等数字是时点采样值，会随真实 PCAP/探针任务持续写入而变化；
  重构前后数字差异来自真实数据继续写入，不是本次结构拆分导致的数据迁移。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-probe-route-split-20260920`。

## 第十二批：集成与离线导入域路由拆分（2026-09-20）

基线 `dc07b2f`，同一分支。目标：按指南 §C 把适配器目录与 `/offline` 导入面收拢成一个域，
路径/方法/鉴权/分页不变；对应后续批次第 1 项的下一个域（指南中记为 integrations/offline）。

已完成代码：

- 新建 `api/integrations.py`（11 条路径）：`GET /integrations`、`POST /integrations/{name}/analyze`、
  `POST /integrations/offline/upload`、`POST /integrations/offline/import`、`GET /offline/resources`、
  `GET /offline/cves`、`POST /offline/upload`、`POST /offline/cves`、`POST /offline/grype/update`、
  `POST /offline/grype/import`、`GET /offline/grype/jobs/{identifier}`；`CveRule`、`job_path`、
  `run_grype_job` 随域下沉，`v1.router` 与既有域一致地只 include 一次、`/api/v1` 前缀只叠加一次。
- `/offline` 原先分散两处：`api/v1.py`（资源/CVE 列表、上传）与 `api/libraries.py`（手工 CVE、Grype
  更新/导入/任务）。本批一并归位，`libraries.py` 只留 dlp 规则、规则源与规则导入（302 → 217 行）。
- 共享边界不复制：适配器元数据/执行仍在 `app.integrations`（registry/runner），离线包解析仍在
  `app.integrations.offline_manager`，Grype 库仍在 `services/grype_library.py`，告警仍在
  `services/alert_service.py`，事件聚合仍走 `incident_engine`，路径校验复用 `core/storage.safe_path`，
  分页复用 `api/pagination.page_response`。
- worker 能力与规则清单读取（原 v1 私有 `_read_worker_capabilities`、`_merge_capability`、
  `_engine_rule_counts`）下沉到共享 `api/runtime_status.py`（改名 `read_worker_capabilities`、
  `merge_capability`、`engine_rule_counts`），`/health` 与 `/integrations` 共用一份实现；
  v1 因此删除已无使用者的 `incident_engine = IncidentEngine()` 句柄（事件聚合逻辑与调用点未变）。
- 从 `libraries.py` 迁出的四条 `/offline` 路由保留原 `rule-libraries` tag（仅文档分组，不涉行为），
  使拆分前后 OpenAPI 排序后仍**字节一致**。
- 新增 `tests/test_integration_offline_boundaries.py`（8 项）：11 条路径/方法冻结、仅由本域声明、
  v1 与 libraries 不再声明 `/integrations*` 与 `/offline*`、libraries 仍保留规则编写面、
  仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、本域不导入 workers/v1/extensions、
  不复制共享守卫、能力读取归 `runtime_status`、v1 只聚合一次。
- 测试迁移：`tests/test_rule_libraries.py` 的独立 app 同时挂 `libraries` 与 `integrations` 子路由；
  `tests/test_gap_fixes.py` 的 monkeypatch 目标由 `app.api.v1` 改到 `app.api.integrations`。

验证：

- 本机 .venv 隔离全量 688 项：681 passed / 6 failed / 1 skipped；6 项失败与第十一批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作，含 tags）；路由仍 162 条记录（158 APIRoute）、
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；158 个操作的「方法 + 路径」首个命中函数完全一致；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 14 个移动定义的 AST 比对：9 个完全相同，5 处差异均为本批声明的改名与 tag 保留；三个能力助手改名后逐节点一致。
- 新增模块/测试 ruff check 与 ruff format 通过；`v1.py`（46 → 26）与 `libraries.py`（15 → 11）ruff 存量只减不增，
  没有顺带批量重排老文件。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy，worker 仍注册 12 个 `security_toolbox.*` 任务名，日志无 Traceback/ERROR/unregistered。
- 真实环境只读复验：登录后 38 个只读接口 + 本域与探针域明细共 41 项全部 200，其中 `/integrations` 8 条、
  `/offline/resources` 1 行、`/offline/cves` 旧数组契约仍为定长数组、分页契约返回 `{items,total,page,page_size}`
  且 `total=394371`；`/test/status present=false`、迁移仍 `0015_alert_hits`（head）；
  本批未导入测试数据、未操作真实探针主机，也未调用 `/offline/*` 的写接口。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-integration-offline-route-split-20260920`。

## 第十三批：规则域路由拆分（2026-09-20）

基线 `052ac15`，同一分支。目标：按指南 §C 把检测引擎规则面收拢成一个域，路径/方法/鉴权/分页不变；
对应后续批次第 1 项的下一个域（指南中记为 rules）。

已完成代码：

- 新建 `api/rules.py`（5 条路径）：`GET /rules`、`GET /rules/content`、`GET /rule-sources`、
  `POST /rules/sync`、`POST /rules`，`RuleSyncRequest`、`DetectionRule` 两个请求模型随域下沉；
  后三条与两个模型原先在 `api/libraries.py`，归位后该文件只保留敏感数据（DLP）规则族 `/dlp/rules*`
  （217 → 101 行），职责从「规则编写 + 漏洞库维护 + 引擎规则」收敛为单一的 DLP 规则目录。
- 共享边界不复制：规则枚举仍只有 `api/rule_presenter.py::rule_file_entries` 一份（`/engine/registry`
  共用），来源出处读 `app.rules.catalog`、`app.rules.library`，在线拉取走 `app.rules.sync`，
  手工 Suricata/YARA 导入走 `app.integrations.offline_manager` 与 `yara` 编译校验（写盘前校验不变），
  `record_audit` 审计不变，`v1.router` 只 include 一次。
- 从 `libraries.py` 迁出的三条路由保留原 `rule-libraries` tag（仅文档分组），使拆分前后 OpenAPI
  排序后仍**字节一致**。
- 新增 `tests/test_rule_boundaries.py`（8 项）：5 条路径/方法冻结、仅由本域声明、v1 与 libraries 不再声明、
  DLP 规则族仍在 libraries、仍挂 `/api/v1` 下、全应用无重复「方法 + 路径」、
  本域不导入 workers/v1/extensions、不复制共享守卫、来源读取走 catalog/sync 服务、
  presenter 仍与 engines 域共用、v1 只聚合一次。
- 测试迁移：`tests/test_rule_libraries.py` 的独立 app 再挂上 `rules` 子路由（与原 `libraries`、
  `integrations` 并列）；上一批的 `tests/test_integration_offline_boundaries.py` 相应收窄为只冻结
  DLP 四条，并断言 `/rules*`、`/rule-sources` 已不属于 libraries。

验证：

- 本机 .venv 隔离全量 697 项：690 passed / 6 failed / 1 skipped；6 项失败与第十二批基线集合完全相同，
  无新增失败、无新增错误。
- 拆分前后 OpenAPI **排序后字节一致**（144 条路径 / 158 个操作，含 tags）；路由仍 162 条记录（158 APIRoute）、
  162 条「方法 + 路径 + 端点函数名」与拆分前逐条相同；158 个操作的首个命中函数完全一致；
  无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 7 个移动定义的 AST 比对：4 个完全相同，3 处差异仅为保留 tag。
- 新增模块/测试 ruff 通过；`v1.py`（26 → 23）与 `libraries.py`（11 → 5）ruff 存量只减不增，
  未批量重排老文件。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy，worker 仍注册 12 个 `security_toolbox.*` 任务名，日志无 Traceback/ERROR/unregistered。
- 真实环境只读复验：登录后 38 个只读接口 + 本域 3 项（`/rule-sources`、`/rules`、`/rules/content`）
  + 探针域 3 项共 44 项全部 200；`/rule-sources` 15 个引擎、键集合与拆分前一致；`/rules` 3512 条、
  14 种类型；`/rules/content` 返回内置/文件规则的正文；`/test/status present=false`、
  迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针主机，
  也未调用 `POST /rules`、`POST /rules/sync` 等写接口。
- 全量偶发第 7 项失败来自既有 flaky `tests/deployment/test_credential.py::test_tamper_rejected`
  （密文末字节恰为 0x00 时篡改等于没改，约 1/256），与本批无关，按约定不在结构移动中顺手修。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-rules-route-split-20260920`。

## 第十四批：v1 剩余零散入口收敛（2026-09-20）

基线 `2da7390`，同一分支。目标：把 `v1.py` 里最后几组零散入口按域收拢，使聚合文件只剩
`include_router`；路径/方法/鉴权/分页不变。

已完成代码：

- 新建四个域，`v1.py` 288 → 79 行，且**自身不再声明任何路径**（只剩兼容重导出与聚合）：
  `api/auth.py`（`POST /auth/login`、`POST /auth/logout`、`GET /auth/me`）、
  `api/health.py`（`GET /health`）、`api/network_scan.py`（`POST /scan`、`GET /scan/{task_id}`）、
  `api/test_data.py`（`POST /test/import`、`POST /test/clear`、`GET /test/status`）。
- 共享边界不复制：会话/口令仍走 `core/security.py` 与 `AdminSession`；`/health` 的 worker 能力与
  规则清单仍读 `api/runtime_status.py`（与 `/integrations` 共用），队列深度读
  `services/task_dispatch.py::queue_depth`，探针行形状读 `api/probe_presenter.py`；`/scan` 的端口
  选择走 `services/scan_service.py`、探针侧排队走 `services/probe_task_service.py`、派发走
  `api/dependencies.dispatch_task`；测试数据导入/清理/状态仍在 `services/test_service.py`。
- 写入口的 opt-in 守卫 `_require_test_data_import`（读 `settings.test_data_import_enabled`，默认关闭）
  随域下沉，两个写入口都必须先过守卫；`main.py` 对 `/api/v1/health` 的免鉴权放行与
  `/api/v1/auth/login` 的公开例外不变，说明「只允许真实数据」的开关仍默认关闭。
- 这四条路径无 tag 变化，OpenAPI 拆分前后**完全一致**（144 条路径 / 158 个操作，含路径顺序）；
  路由仍 162 条记录（158 APIRoute），路径/方法/端点函数名多重集与拆分前完全相同，仅注册顺序变化。
- 新增 `tests/test_auth_boundaries.py`（7 项，含「`v1.py` 自身不再声明任何路径」这条总约束）、
  `tests/test_health_boundaries.py`（7 项）、`tests/test_network_scan_boundaries.py`（8 项，含
  `/scan` 与 `/scan/{task_id}` 与 `/scan-profiles*` 不互相遮蔽）、`tests/test_test_data_boundaries.py`（7 项，
  含守卫只有一个实现、两个写入口都过守卫）。
- 测试迁移：`tests/test_integration_offline_boundaries.py` 的 worker 能力共用断言由 `v1.py` 改指
  `api/health.py`（`/health` 迁出后 v1 不再导入 `runtime_status`）。

验证：

- 本机 .venv 隔离全量 726 项：719 passed / 6 failed / 1 skipped；6 项失败与第十三批基线集合完全相同，
  无新增失败、无新增错误（其中 29 项为本批新增边界测试）。
- 拆分前后 OpenAPI **完全一致**（144 条路径 / 158 个操作，含路径顺序与 tags）；路由仍 162 条记录
  （158 APIRoute）、158 条「路径 + 方法」多重集相同；158 个操作的首个命中函数完全一致；
  10 个被移动定义的 AST 逐节点比对完全相同；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- 新增模块/测试 ruff check 与 format 一次通过；`v1.py` ruff 存量 23 → 0（14 E501、9 B008 随代码迁出），
  未批量重排老文件。
- 镜像用 legacy builder 重建并切换 backend/worker/beat/deployment-worker（未改前端，未重建 frontend）：
  四容器 healthy，worker 仍注册 12 个 `security_toolbox.*` 任务名，日志无 Traceback/ERROR/unregistered。
- 真实环境只读复验：登录后 35 个只读接口 + 本批 3 项（`/auth/me`、`/health`、`/test/status`）
  + 规则域 3 项 + 探针域 3 项共 44 项全部 200；`/health` 返回 status=ok、redis=ok、
  analysis_worker=ready、`features.test_data_import=false`；`/test/status present=false`；
  迁移仍 `0015_alert_hits`（head）；本批未导入测试数据、未操作真实探针主机，
  也未调用 `POST /test/import`、`POST /test/clear` 等写接口。
- 回退标签 `source-{backend,worker,beat,deployment-worker}:pre-v1-residual-route-split-20260920`。

## 第十五批：前端 PCAP 工作台状态解耦（2026-09-20）

基线 `e7eb701`，同一分支。目标：按指南 §F「前端先抽状态，再抽视图」把工作台的状态与 API 编排
从组件里抽出来，模板与交互不变。

已完成代码：

- 新增 `frontend/src/modules/network/pcap/composables/usePcapWorkbench.ts`（382 行），
  `PcapWorkbench.vue` 只保留模板、弹窗与格式化（582 → 312 行）；迁入的 278 行脚本逐行比对，
  只有两处声明过的改动：`streamData` 改用 `api/pcaps.ts` 已有的 `TcpStreamFollow` 类型
  （原来重复声明了一份等价的内联类型），以及新增 `closeFileDialog()`。
- 模板原来在弹窗 `@closed` 上直接 `++fileVersion`；`let` 计数器不能通过 composable 的返回值
  暴露成活绑定（返回值只是取值拷贝），因此改为调用 `closeFileDialog()`，语义不变：
  关弹窗即作废在途的文件预览请求。
- 过期响应防护与轮询原样保留：`viewVersion`（切换抓包）、`packetVersion`（包分页）、
  `detailVersion`（包详情）、`fileVersion`（文件预览）、`taskVersion`（分析轮询）；
  轮询 timer 在组件卸载时清除，离开页面即停止轮询（指南 §F 第 3 条）。API 仍只走
  `frontend/src/api`，没有第二套 HTTP 客户端。
- 新增 `frontend/src/__tests__/pcap-workbench-state.test.ts`（9 项）：列表失败进页面状态、
  两次打开抓包的竞态只保留最新、去重上传定位到记录并清空筛选、空文件拒绝且不调 API、
  包分页按当前查询并丢弃过期页、TCP 流跟踪与文件预览（无保留字节时拒绝）、
  关弹窗后丢弃迟到的预览、分析轮询成功后重开抓包、返回列表并重新加载。

验证：

- `npm run typecheck` 通过；全量 vitest 11 个文件 46 项通过（原 37 项 + 本批 9 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：容器 Up，
  `http://localhost:8088/`、入口 chunk 与 `PcapWorkbench` chunk 均 200，入口 chunk 名与本地构建一致，
  工作台 chunk 内仍是真实 API 调用、无 demo/mock 代码；本批未导入测试数据、未操作真实探针主机。
- 回退标签 `source-frontend:pre-pcap-workbench-state-20260920`。

## 第十六批：前端数据资产采集任务页状态解耦（2026-09-20）

基线 `1abca8c`，同一分支。目标：按指南 §F「前端先抽状态，再抽视图」把采集任务页的状态、派发与
轮询从组件里抽出来，模板与交互不变。

已完成代码：

- 新增 `frontend/src/modules/data-security/composables/useDataAssetJobs.ts`（159 行），
  `DataAssetJobs.vue` 只保留模板与按钮（251 → 131 行）；迁入的 113 行脚本逐行比对，
  只有一处声明过的改动：任务列表原来由页面直接调 `apiGet('/tasks', ...)`，改用
  `api/tasks.ts::listTasks`（同一个请求）。
- 探针与扫描配置下拉、任务列表、派发/取消/移除与统计卡计数仍在 composable；5 秒自动刷新 timer 归
  composable 所有，`onMounted` 启动、`onBeforeUnmount` 清除，离开页面即停止轮询（指南 §F 第 3 条）。
- 派发 payload 语义原样保留：显式路径按行切分并去空行，优先于扫描配置；路径非空且选了配置时两个
  字段都发；没有选中探针时不发请求。API 仍只走 `frontend/src/api`，没有第二套 HTTP 客户端。
- 新增 `frontend/src/__tests__/data-asset-jobs-state.test.ts`（9 项）：加载探针/配置/任务与默认选中、
  加载失败进页面状态、统计卡计数、路径优先 payload、空路径只发 profile_id、无探针拒绝派发、
  派发失败不改任务列表、取消/移除后刷新、5 秒轮询与关闭自动刷新、卸载停止轮询。

验证：

- `npm run typecheck` 通过；全量 vitest 12 个文件 55 项通过（原 46 项 + 本批 9 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `DataAssetJobs` chunk 均 200，线上 chunk 与本地
  构建 SHA256 一致、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/tasks?kind=data_asset_scan`、`/probes`、`/scan-profiles`、`/data/assets`、`/data-types`、
  `/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；
  本批未导入测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-data-asset-jobs-state-20260920`。

## 第十七批：前端数据目录类型页状态解耦（2026-09-20）

基线 `290dbc1`，同一分支。目标：按指南 §F 把数据类型中心与类型详情的状态从组件里抽出来，
模板与交互不变。

已完成代码：

- 新增 `frontend/src/modules/data-security/composables/useDataTypeCenter.ts`（64 行）与
  `useDataTypeDetail.ts`（68 行）；`DataTypeCenter.vue` 154 → 117 行、`DataTypeDetail.vue` 134 → 99 行，
  两个页面只保留模板与行跳转。迁入的 37 行与 35 行脚本逐行比对未改。
- 两处声明过的改动：类型详情的路由 `category` 改为由页面传入的 `ComputedRef`（composable 不再自己
  调 `useRoute`），并新增 `setPage()`；模板分页由 `@current-change="(value) => (page = value)"` 改为
  `@current-change="setPage"`——composable 返回的 ref 不能在模板里直接赋值（同 PCAP 批的
  `closeFileDialog`）。
- 顶部卡片继续直接用服务端去重后的 `totals`/`totals_scope`，不把每行相加；`search` 只过滤表格，
  不改总数；失败的刷新保留上一次成功的数据。
- 新增 `frontend/src/__tests__/data-type-catalog-state.test.ts`（7 项）：加载行与分级目录并保留
  服务端 totals 与范围标签、按类型/实体过滤且总数不变、失败刷新保留旧数据、按路由 category 加载、
  翻页与换类型重新查询、身份徽标四态（确认/疑似副本/待确认身份/作用域内）、失败进页面状态。

验证：

- `npm run typecheck` 通过；全量 vitest 13 个文件 62 项通过（原 55 项 + 本批 7 项）；
  生产构建 `npm run build`（未启用 `VITE_DEMO_MODE`）通过。
- 前端镜像用 legacy builder 重建并切换 `source-frontend:latest`（后端未改，四个后端容器未重建）：
  容器 Up，`http://localhost:8088/`、入口 chunk 与 `DataTypeCenter`/`DataTypeDetail` chunk 均 200，
  chunk 名与本地构建一致、线上字节 SHA256 相同、无 demo/mock 代码。
- 真实环境只读复验：`/health`、`/test/status`（`present=false`）、`/auth/me`、
  `/tasks?kind=data_asset_scan`、`/probes`、`/scan-profiles`、`/data/assets`、`/data-types`、
  `/data-objects`、`/asset-instances`、`/sensitive/findings`、`/sensitivity-levels` 均 200；
  本批未导入测试数据、未操作真实探针主机；后端未重建，迁移仍 `0015_alert_hits`（head）。
- 回退标签 `source-frontend:pre-data-type-catalog-state-20260920`。

## 后续批次（尚未实施，不宣称全项目解耦完成）

后端路由已全部按域拆出（`v1.py` 只做聚合）。剩余：

1. 前端对象详情、实例详情页按实际需求逐批拆分（同一模式：先抽状态，再抽视图；
   PCAP 工作台、采集任务页与类型页的状态已完成）。
2. 模型包拆分放在业务依赖稳定之后；最后独立处理探针模块及分发包，不擅自升级真实主机。
3. 旧的 `workers/tasks.py` 兼容门面、`data_object_service.py` 与 `v1.py` 里的兼容重导出
   在确无调用方后再删除。

不要把本批的结构移动与历史数据回填或检测规则修改混在一起。

## 历史

- [本批前任务全文](docs/history/task-before-data-asset-refactor-2026-09-19.md)
- [本批前项目状态全文](docs/history/project_status-before-data-asset-refactor-2026-09-19.md)
- [v2.12.0 发布记录](docs/releases/v2.12.0.md)
- [总体解耦指南](docs/解耦操作指南.md)
