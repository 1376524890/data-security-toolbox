# 项目状态

更新时间：2026-09-20。当前任务见 TASK.md；稳定约束见 AGENTS.md；模块关系见 docs/architecture.md。
历史时点数字与旧问题讨论已移至 [本批前完整状态](docs/history/project_status-before-data-asset-refactor-2026-09-19.md)。

## 版本与工作分支

| 项目 | 当前值 |
| --- | --- |
| 最近发布 | Git 注释标签 v2.12.0，发布提交 d1c1569 |
| 源码内平台版本 | 2.11.0（上一轮按不改代码约定保留，本轮不发新版本） |
| 探针源码版本 | 3.5.0；本轮未改探针或分发包 |
| 本批基线 / 分支 | 9833cad / refactor/data-asset-boundaries |
| 数据库迁移 | 0015_alert_hits；本批无模型/表结构变更 |
| 本批范围 | 第三批：PCAP 域路由拆分；前两批（数据资产边界、分析编排与 Celery 入口）见下方记录 |

## 本批已落地结构

- PCAP 域路由独立为 `api/pcaps.py`（18 条路径：上传、列表/详情/分析、包/流、协议/流量、DNS/HTTP/TLS、
  提取清单/预览/下载、抓包告警、文件末尾兼容下载端点），由 `v1.router` 只 include 一次，前缀只叠加一次。
- 上传归属与队列背压移到 `api/dependencies.py`（`upload_probe_id`、`enforce_queue_backpressure`），
  Task 行序列化移到 `api/task_presenter.py`；PCAP 域与 tasks 路由共用同一实现，不复制规则。
- 第二批边界维持：平台资产/IOC 身份解析（`domain/evidence_identity.py`）、跨域分析编排
  （`application/analysis.py`）、任务行持久化（`services/task_service.py`）与队列派发端口
  （`services/task_dispatch.py`）分层独立；worker 分 analysis/notification/maintenance 三模块，
  加 `task_runtime.py`、`task_names.py`；旧 `workers/tasks.py` 仅 43 行兼容门面；API 不再导入 `app.workers.*`。
- 第一批边界维持：采集 schema/路由/任务创建/错误映射独立，数据对象按职责分模块，旧服务文件仅兼容导出；
  旧资产展示与敏感发现路由在 data_assets，前端 DataAsset 页面仅组装列表/详情与采集状态。
- 具体功能修改入口见 [数据资产开发入口](docs/数据资产开发入口.md)。

| 文件 | 拆分前行数（首次） | 当前行数 |
| --- | ---: | ---: |
| backend/app/api/v1.py | 2557 | 2121 |
| backend/app/api/pcaps.py | 0（本批新增） | 649 |
| backend/app/api/task_presenter.py | 0（本批新增） | 25 |
| backend/app/api/dependencies.py | 12 | 49 |
| backend/app/api/extensions.py | 718 | 364 |
| backend/app/services/data_object_service.py | 1165 | 58（兼容导出） |
| backend/app/workers/tasks.py | 981 | 43（兼容门面） |
| backend/app/incident_engine/engine.py | 344 | 263（身份解析移出） |
| frontend/src/modules/data-security/DataAsset.vue | 285 | 144 |

逻辑被移动到有明确职责的模块，不是删除功能；不得用总行数变化代替维护效率评估。

## 验证与已知限制

- 第三批（本机 .venv 隔离全量）614 项：607 passed / 6 failed / 1 skipped；6 项失败与第二批基线集合完全相同。
- 拆分前后 OpenAPI 字节一致（144 条路径 / 158 个操作）；路由仍 162 条记录（158 APIRoute / 148 路径），
  端点函数名集合一致；无数据库变更，迁移仍 `0015_alert_hits`（head）。
- PCAP 行为回归：`tests/test_pcap_workbench.py` 除本机缺少原生导出器 1 项外全部通过。
- 第二批（本机 .venv 隔离全量）608 项：601 passed / 6 failed / 1 skipped。同一提交的干净检出失败 16 项
  （多出的是本机未构建探针分发包导致的 10 项），本批 6 项失败均为其子集，无新增失败。
- 当前 6 项失败与拆分无关：tshark 看门狗与 PCAP 索引上限 2 项、协议引擎夹具 1 项、探针身份注册 1 项、
  PCAP 工作台原生导出 1 项、health 在本机环境判定为 degraded 1 项；尚未修复，也未因本批改变。
- 第一批（容器环境）记录：582 passed / 17 failed，其同环境基线 579 passed / 17 failed，失败集合一致；
  分发包/挂载布局 14 项、缺 Redis/worker 能力 2 项、Zeek 相对 PCAP 路径 1 项。历史数字按当时口径保留。
- 前端本批未改：类型检查、37 项测试、生产构建沿用第一批结论。
- 路由仍为 162 条记录（158 APIRoute / 144 路径），与拆分前一致；无数据库迁移。
- 边界检查累计：`tests/test_task_boundaries.py`（9 项）、`tests/test_data_asset_boundaries.py`（3 项）、
  `tests/test_pcap_boundaries.py`（6 项）。
- 新增/拆出模块 ruff 与 ruff format 通过；`v1.py` 只减不增（清理了拆分造成的 7 处未使用导入），
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

## 已有系统能力

探针采集/心跳/受控任务；资产、文件与 PCAP 分析；共享敏感识别与扫描预算；数据对象/实例/旧投影；
引擎规则库与命中解释；事件关联与告警；情报适配；报告；探针部署/回收；Vue 控制台与 Docker 部署。
探针只做采集相关工作，服务端承担评分、关联与报告；交付环境只允许真实数据。

## 剩余事项

- 其余大路由、其他前端页面、模型包和探针尚按总体指南待拆分（PCAP 域路由、分析任务编排与 Celery 入口已完成）。
- 历史对象计数/投影/告警命中回填仍是独立任务；只读 remediation_dry_run 工具已存在，不能默认执行修复。
- 旧测试布局与既有失败需单独解决，不在结构移动中绕过测试。
- 旧代码 ruff 存量仍存在；仅约束本次新增/变更内容，不全仓格式化。
- 旧门面（`workers/tasks.py`、`data_object_service.py`）在确无调用方后再删除。

本批不变更外部 API、数据库定义、Celery 任务名、任务协议和真实探针版本；旧 Python 入口暂保留兼容导出。
