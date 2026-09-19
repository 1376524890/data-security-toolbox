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

## 后续批次（尚未实施，不宣称全项目解耦完成）

1. 继续按域拆其余 v1 路由，重点明确文件/PCAP 对数据资产结果的写入边界。
2. 前端类型中心、对象详情、采集任务页与 PCAP 工作台按实际需求逐批拆分。
3. 模型包拆分放在业务依赖稳定之后；最后独立处理探针模块及分发包，不擅自升级真实主机。
4. 旧的 `workers/tasks.py` 兼容门面与 `data_object_service.py` 在确无调用方后再删除。

不要把本批的结构移动与历史数据回填或检测规则修改混在一起。

## 历史

- [本批前任务全文](docs/history/task-before-data-asset-refactor-2026-09-19.md)
- [本批前项目状态全文](docs/history/project_status-before-data-asset-refactor-2026-09-19.md)
- [v2.12.0 发布记录](docs/releases/v2.12.0.md)
- [总体解耦指南](docs/解耦操作指南.md)
