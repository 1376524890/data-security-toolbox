# 阶段 4 实施记录：DataObject / AssetInstance / Detection / Evidence 与聚合口径

- 前置：`docs/data-discovery-3.3.1-baseline.md`（阶段 0）、`docs/data-discovery-stage1-shared-engine.md`（阶段 1）、`docs/data-discovery-stage2-ruleset.md`（阶段 2）、`docs/data-discovery-stage3-scanprofile.md`（阶段 3）。
- 基线版本：平台 2.7.0 / 探针 3.3.1；本阶段**不递增版本号**（版本号在阶段 6 统一提升）。
- 本记录中所有数字均为本机实测，命令与结果见第 7 节；未验证项目集中在第 8 节。
- 部署凭据（SSH、探针 token、数据库口令）不写入本记录、代码或日志；需要凭据的验证均在已授权会话内完成。

## 1. 阶段完成判定

| 阶段 4 要求 | 实测证据 |
|---|---|
| DataObject 逻辑对象 | `backend/app/models.py::DataObject`（`data_objects`，18 列）：`object_key`(唯一)、`object_type`、`content_hash`、`hash_type`、`identity_confidence`、`partial_version`/`partial_layout`、`size`、`first_seen_at`/`last_seen_at`、`instance_count`/`active_instance_count`、`categories`、`sensitivity`、`extra` |
| AssetInstance 物理实例 | `AssetInstance`（`asset_instances`，31 列），`UNIQUE(probe_id, path)`（`uq_asset_instance_probe_path`）；实例身份就是"探针 + 规范化绝对路径"，改名/移动产生新实例，绝不复用旧实例 ID |
| Detection 检测汇总 | `Detection`（`detections`，20 列），`UNIQUE(instance_id, category, object_id)`（`uq_detection_instance_category_object`）；含 `sensitivity_level`(L1..L4)、`severity`(旧词表)、`confidence`、`sample_size`、`sample_hit_count`、`hit_count`、`engine_version`、`ruleset_version` |
| DetectionEvidence 证据 | `DetectionEvidence`（`detection_evidence`，18 列），`UNIQUE(detection_id, evidence_key)`；只有 `rule_id`/`rule_name`/`rule_source`/`recognizer`/`evidence_type`/`field_name`/`sheet_name`/`column_index`/`confidence`/`hit_count`，**不存在任何存值的列** |
| 完整 SHA256 才聚合 | `resolve_identity()`：`hash_type='full_sha256'` 时 `object_key = sha256:<值>`，`identity_confidence=1.0`；用例 `test_equal_full_hash_forms_one_object_and_two_instances`、`test_different_hashes_never_merge` |
| 部分指纹只形成候选 | `fingerprint.PARTIAL_VERSION='1.0.0'` → `object_key = partial:<version>:<hash>`，`identity_confidence=0.5`；候选副本单独计数，不进"确认副本"（`data_type_rows`） |
| 无可靠 Hash 时作用域内独立身份 | `object_key = scoped:<盐>:<probe_id>:<object_type>:<path 哈希>`，`identity_confidence=0.0`；**不**用空 Hash、文件名或大小去重 |
| 同路径内容改变保留历史归属 | `Detection` 主键含 `object_id`：内容变了实例指向新对象、新 Detection，旧对象保留自己的 Detection；用例 `test_content_change_keeps_the_previous_object_history` |
| Scope 完整扫描才可标记 NOT_OBSERVED | `complete_scope()` + `sweep_scope(..., allow_sweep=covered)`；超时/取消/部分/带 error 的报告一律不扫；用例 `test_incomplete_scope_never_declares_data_gone`、`test_legacy_report_with_an_error_still_never_sweeps` |
| 迟到报告不改变已有结论 | `_is_late()` 按 `last_scan_at` 判定；迟到报告只累加 `instance.extra['stale_reports_ignored']`，不回滚 `last_seen`、当前对象或当前 Detection；用例 `test_a_late_report_never_rolls_back_the_current_state` |
| 并发上传靠唯一约束与事务 | `_get_or_create()` 先查后插但以 `IntegrityError` 兜底（`begin_nested()` savepoint 后重读）；整份报告在一个事务内落库 |
| 旧投影保留为派生视图 | `data_assets` 由 `project_asset()` 在同一事务内写出，`rebuild_projection()` 可从新表恢复；用例 `test_projection_can_be_rebuilt_from_the_object_model` |
| 旧记录一次性回填 | `backfill_legacy()`：把存量 `data_assets` 投影为实例，`extra={'backfilled': True, 'metadata': 'unknown'}`，**不臆造** hash/inode/权限；用例 `test_backfill_projects_legacy_rows_without_inventing_metadata` |
| 数据类型聚合口径可解释 | `data_type_rows()`：对象数按 `object_id` 去重、主机数按 `probe_id` 去重、确认副本按对象计 `max(active_instance_count - 1, 0)` 求和、候选副本单独成列 |
| 分级与旧严重度不混淆 | `services/sensitivity_map.py`：`L1..L4` 是新维度，`Critical/High/Medium/Low` 仅作为派生值保留；`GET /api/v1/sensitivity-levels` 同时给出映射、来源（`builtin_default`/`settings_override`）与"不产生敏感"的结构性实体清单 |
| P0 查询 API | `backend/app/api/data_catalog.py`（11 个端点，见第 3 节）；`extensions.py` 的 `POST /probes/{id}/data-assets` 返回 `scan_id`/`complete_scope`/`not_observed`/`stale` |
| 任务进度上报 | `POST /api/v1/probes/{probe_id}/data-assets/progress`（探针侧 5 秒限流）；只更新 `progress`/`current_stage`/`result['coverage']`，**不推进任务状态** |
| 迁移可升级、可回滚、不丢旧数据 | `0012_asset_objects`：纯增量 4 表 + 索引，FK 用 `ALTER TABLE` 后置添加；实测见第 7 节 |

## 2. 数据模型与迁移

新增四张表（`backend/app/models.py`，插入位置在 `GraphRelation` 之前）：

| 表 | 列数 | 关键约束 / 索引 |
|---|---|---|
| `data_objects` | 18 | `uq_data_object_key`；`ix_data_objects_{object_key,object_type,content_hash,hash_type,sensitivity}` |
| `asset_instances` | 31 | `uq_asset_instance_probe_path`；`ix_asset_instances_{object_id,probe_id,instance_type,status,scope_key,last_scan_id,sensitivity}` |
| `detections` | 20 | `uq_detection_instance_category_object`；`ix_detections_{object_id,instance_id,probe_id,scan_id,category,sensitivity_level,severity}` |
| `detection_evidence` | 18 | `uq_detection_evidence_key`；`ix_detection_evidence_{detection_id,rule_id}` |

外键（6 条，实测 `pg_constraint` 列名）：

`fk_asset_instances_object_id` → `data_objects`、`fk_asset_instances_probe_id` → `probes`、`fk_detections_object_id` → `data_objects`、`fk_detections_instance_id` → `asset_instances`、`fk_detections_probe_id` → `probes`、`fk_detection_evidence_detection_id` → `detections`。

`backend/alembic/versions/0012_asset_objects.py`（`down_revision = 0011_scan_profiles`）：

- `upgrade()` 只 `CREATE TABLE` / `CREATE INDEX` / `CREATE FOREIGN KEY`，无 `DROP`、无 `TRUNCATE`、不改既有列；
- 顶部 `_has_table()` 守卫，因此"空库直接到 head"与"库停在 0011"走同一条安全分支；
- 外键统一在 `_FOREIGN_KEYS` 元组里**最后**添加，并用 `_supports_add_constraint()` 在 SQLite 上跳过（Alembic 的 SQLite 方言不支持 `ALTER TABLE ADD CONSTRAINT`），保证 PostgreSQL 与 SQLite 两侧都能建表；
- `downgrade()` 按 `detection_evidence → detections → asset_instances → data_objects` 顺序删除，即子表先删，避免悬空外键。

### 2.1 "当前视图"与"历史观测"的存储边界

- **当前视图**：`instance.object_id` 指向实例当前内容的对象；`Detection(instance_id, category, object_id)` 中 `object_id == instance.object_id` 的那些行。
- **历史观测**：内容变化后，旧对象的 Detection/Evidence 仍然挂着旧 `object_id`，不会被覆盖；查询历史用 `object_id`，查询现状用 `instance.object_id`。
- 因此 `UNIQUE(instance_id, category)` **不够**：它会在内容变化时把旧对象的 Detection 覆盖掉，所以唯一键必须包含 `object_id`。

### 2.2 探针删除时的对象模型语义

`AssetInstance` 的身份是 `(probe_id, 路径)`，探针被删除后这个身份无法重建，所以 `DELETE /api/v1/probes/{id}` 会在原有"保留采集记录、清空外键"逻辑之后调用 `data_object_service.forget_probe()`：删除该探针的实例、检测与证据，保留**逻辑对象**（其它探针可能持有同样内容），并重算受影响对象的计数。

存量 `data_assets` 投影行完全不动，与旧行为一致（旧代码同样只清空 `probe_id`、保留记录）。

## 3. 对象模型服务与 API

`backend/app/services/data_object_service.py`（约 800 行）关键入口：

| 函数 | 职责 |
|---|---|
| `resolve_identity()` | 按 `full_sha256` / `partial_fingerprint` / `scoped` 三档产出 `object_key` 与 `identity_confidence` |
| `normalise_path()` / `in_scope()` | 绝对路径规范化；复刻旧的 scope 判定（root 相对层级 ≤ `max_depth + (目录?0:1)`），使 sweep 不会意外扩大 |
| `complete_scope()` | 1.1 报告看 `completed_scope`；旧报告沿用 `complete` 的**默认值 True**语义 |
| `ingest_report()` | 单事务写入：对象 upsert、实例 upsert、Detection 合并、Evidence 去重、投影同步、sweep、计数重算 |
| `sweep_scope()` | 仅在 `allow_sweep` 为真时，把本报告 roots 内未见到的 ACTIVE 实例置为 `NOT_OBSERVED` |
| `forget_probe()` | 探针删除时清理该探针的观测状态 |
| `rebuild_projection()` / `backfill_legacy()` | 投影恢复与旧记录一次性回填 |
| `data_type_rows()` / `object_detail()` / `instance_detail()` | 页面查询口径 |

`backend/app/api/data_catalog.py`（实际实现路径，全部挂在 `/api/v1` 下）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/data-types` | 数据类型列表；`?probe_id=` 可限定探针 |
| GET | `/data-types/{category}` | 单一类型详情（含分级解释） |
| GET | `/data-objects` | 对象列表（分页 + 白名单排序 + 过滤） |
| GET | `/data-objects/{object_id}` | 对象详情（实例数、活跃实例数、首个/最近发现） |
| GET | `/data-objects/{object_id}/detections` | 某对象的检测（分页） |
| GET | `/asset-instances` | 实例列表（分页 + 白名单排序 + 过滤） |
| GET | `/asset-instances/{instance_id}` | 实例详情；`?include_history=true` 附加历史对象与检测 |
| GET | `/detections/{detection_id}/evidence` | 证据（规则/识别器/字段/表头/列序号/置信度，无匹配值） |
| GET | `/sensitivity-levels` | L1..L4 映射、来源、结构性实体（不产生敏感的类型） |
| POST | `/admin/data-assets/rebuild-projection` | 从新表恢复旧投影（管理员，写审计） |
| POST | `/admin/data-assets/backfill` | 存量投影一次性回填（管理员，写审计） |

排序白名单：未知 `order_by` 直接 400（用例 `test_lists_reject_an_unsupported_sort_and_paginate`），不做静默回退。

`extensions.py` 侧新增：

- `POST /probes/{probe_id}/data-assets`（旧路径保留）现在调用 `ingest_report()`，返回体新增 `scan_id`、`complete_scope`、`not_observed`、`stale`；`task.result['schema_version']` 记录识别到的报告版本；
- `POST /probes/{probe_id}/data-assets/progress`（新）：探针投递 `coverage`/当前路径，服务端只更新进度字段，`progress_percent()` 返回 `{percent, estimated, basis}`，`estimated` 如实标注该百分比是估算值。

## 4. 探针侧改动

- `probe/data_assets.py`：`REPORT_SCHEMA_VERSION='1.1'`；`PROGRESS_INTERVAL_SECONDS=5.0`；`_hit_summary()` 现在输出逐规则 `evidence` 列表；`_columns_from_result()` 遍历 `result.sheets → sheet.columns`，补 `header_name`/`sheet_name`/`column_index`/`inferred_type`/`sample_size`/`rule_ids`；`discover_data_assets(config, stop_event=None, on_progress=None)` 按 5 秒限流回调；报告新增 `schema_version`/`scan_id`/`profile_version`/`completed_scope`/`termination_reason`/`budget`/`totals`/`degraded_capabilities`。
- `probe/probe.py`：`_run_data_asset_job()` 生成 `merged['scan_id'] = uuid4().hex`，并把 `on_progress` 接到新的 `_report_progress()`；该方法投递失败时**吞掉所有异常**，进度上报绝不能影响扫描本身。
- `backend/tests/probe/test_task_cancellation.py`：桩函数签名跟进 `on_progress` —— 新参数是可选关键字参数，3.3.1 时期写死的两参桩会 `TypeError`。这是"新接口必须向后兼容旧调用方"在测试侧的直接体现。

## 5. 修复的真实缺陷

阶段 4 发现并修复了 3 个**会产生错误结论或错误行为**的问题，全部有回归用例；每个都记录"修复前的可观测证据"。

1. **旧报告不再标记"未观测到"（最严重）**。`complete_scope()` 第一版要求报告显式给出 `complete`，但 3.3.1 的 `ProbeDataAssetReport.complete` 是 `bool = True`（缺省即"走完了"）。缺省字段因此被判为 `False` → 永不 sweep → **真实删除的文件会永远停留在 `observed`**，而这正是本模型最不能产生的结论。
   - 证据：`pytest backend/tests/test_probe_task_lifecycle.py::test_inventory_identity_and_scope_use_full_path` 在修复前失败（`{'/a/users.csv': 'observed'} != {'/a/users.csv': 'not_observed'}`），修复后通过。
   - 修复：`payload.get("complete", True)`；显式 `false` 与带 `error` 的报告仍然不 sweep。
   - 回归用例：`test_legacy_report_without_a_complete_flag_still_sweeps`、`test_legacy_report_with_an_error_still_never_sweeps`。
2. **收缩 root 列表会让文件永远"在观测中"**。`sweep_scope()` 第一版按存储的 `scope_key` 过滤，而 `scope_key` 绑定了完整 root 集合。探针先扫 `['/a','/b']`、再扫 `['/a']` 时，`/a` 下的文件 `scope_key` 不相等 → 不 sweep → 一个确实被删掉的 `/a/users.csv` 会永远显示 `observed`。
   - 证据：同一条用例（上面的失败信息里 `/a/users.csv` 就是被 `['/a']` 这一次完整扫描漏掉的文件）。
   - 修复：只用 `in_scope()` 对**本次报告的 roots 与深度**判定；`scope_key` 仍保存与上报，但仅作溯源。
3. **有实例的探针在 PostgreSQL 上无法删除**。新增的 `fk_asset_instances_probe_id` 让 `DELETE /api/v1/probes/{id}`（内部 `db.delete(probe)`）被数据库拒绝，而该端点此前并不感知新表。
   - 证据：实测 scratch 库 `dst_mig4`，在探针已被一个实例引用时执行 `delete from probes where name='p';` → `ERROR: update or delete on table "probes" violates foreign key constraint "fk_asset_instances_probe_id" on table "asset_instances"`。
   - 修复：`delete_probe` 在原有"保留采集记录、清空外键"之后调用 `forget_probe()`。
   - 回归用例：`test_deleting_a_probe_removes_its_observation_state_but_not_the_objects`。

另有一处**测试隔离**问题被记录而非"修绿"：SQLite 会把被删除的最大 rowid 交给下一次 INSERT。实测中，本阶段新增的"删除探针"用例先删除当时 id 最大的探针，随后 `test_probe_task_lifecycle.py` 注册的 `lifecycle-pending` 复用了同一个 id，于是继承了前一个探针遗留的 `data_asset_scan` 任务行，导致该文件的 `assert client.get(f'/api/v1/probes/{probe}/tasks').json() == []` 失败（该用例单独运行时通过）。`test_deleting_a_probe...` 因此先注册一个占位探针再删除被测探针，并在注释中写明原因（PostgreSQL 序列不会复用 id，生产环境不存在该现象）。

## 6. 测试

| 文件 | 用例数 | 覆盖 |
|---|---|---|
| `backend/tests/test_data_objects.py`（新增） | 23 | 身份：`test_equal_full_hash_forms_one_object_and_two_instances`、`test_different_content_and_missing_hash_never_merge`、`test_partial_fingerprint_is_a_labelled_candidate_not_a_duplicate`、`test_same_hash_on_two_probes_shares_the_object_but_not_the_host`。检测：`test_one_detection_per_instance_and_type_with_deduplicated_evidence`、`test_detection_never_carries_a_matched_value`（断言模型中不存在任何存值列）。生命周期：`test_complete_scope_marks_unseen_instances_not_observed`、`test_incomplete_scope_never_declares_data_gone`、`test_instance_outside_the_scanned_depth_is_left_alone`、`test_renaming_creates_a_new_instance_and_the_old_one_is_not_repointed`、`test_content_change_keeps_the_old_objects_detections_as_history`、`test_late_report_cannot_roll_back_a_newer_scan`。旧协议兼容：`test_legacy_331_report_still_ingests_and_keeps_working`、`test_legacy_report_with_an_error_still_never_sweeps`、`test_legacy_report_without_a_complete_flag_still_sweeps`、`test_unknown_report_schema_is_treated_as_the_legacy_shape`。其余：`test_projection_can_be_rebuilt_from_the_object_model`、`test_backfill_projects_legacy_rows_without_inventing_metadata`、`test_progress_updates_the_task_without_touching_its_status`、`test_progress_is_rejected_for_another_probe_or_an_unknown_task`、`test_lists_reject_an_unsupported_sort_and_paginate`、`test_level_mapping_is_explainable_and_never_overwrites_the_legacy_field`、`test_deleting_a_probe_removes_its_observation_state_but_not_the_objects` |
| `backend/tests/probe/test_task_cancellation.py`（更新） | 4 | `discover_data_assets` 桩签名跟进 `on_progress`；空 `paths` 仍取本地配置 |
| `backend/tests/shared/**`（回归） | 124 | 阶段 1–3 的共享层契约，本阶段未改动共享层语义 |

## 7. 本次实测命令与结果

| 验证项 | 命令 | 结果 |
|---|---|---|
| 迁移（生产路径 0011→0012） | 容器内 `alembic upgrade 0011_scan_profiles` → `alembic upgrade head`（scratch 库 `dst_mig4`） | 成功，`0012_asset_objects (head)` |
| 迁移幂等 | 再次 `alembic upgrade head` | 无操作，仍为 head |
| 迁移往返 | `alembic downgrade 0011_scan_profiles` → 查表数 → `upgrade head` | 降级后 4 张表计数为 `0`，再升级回到 `0012_asset_objects (head)` |
| 全新库路径 | 空库 `dst_fresh4` 直接 `alembic upgrade head` | 成功，`alembic_version = 0012_asset_objects` |
| 表结构 | `information_schema.columns group by table_name` | `data_objects` 18、`asset_instances` 31、`detections` 20、`detection_evidence` 18 |
| 索引 | `pg_indexes` | 29 条（含 4 个主键、4 个唯一键与 21 个普通索引） |
| 外键 | `pg_constraint where contype='f'` | 6 条，目标表为 `data_objects`/`probes`/`asset_instances`/`detections` |
| 外键真实生效（子表） | 在 scratch 库插入实例后 `delete from asset_instances` | 被 `fk_detections_instance_id` 拒绝：`update or delete on table "asset_instances" violates foreign key constraint` |
| 外键真实生效（探针） | 在 scratch 库插入实例后 `delete from probes where name='p'` | 被 `fk_asset_instances_probe_id` 拒绝：`update or delete on table "probes" violates foreign key constraint`；即修复前 `DELETE /api/v1/probes/{id}` 在该探针有实例时必然失败 |
| 探针包构建 | `python probe_packages/build_packages.py` | amd64 `sha256=f6bb2847289eee8cdb619f636f231a128316b6838ada26ff84a46ac6b279755b`、arm64 `sha256=51421a2eb23bdfe1443acd02e7b2b8c3a4d4e19fe632719e8c3c1664562e4eaf`；manifest 32 个文件，含 `shared/scanning/**` 13 个，无 `__pycache__` |
| 静态检查（本阶段改动） | `ruff check --select E9,F,B backend/app/services/data_object_service.py backend/tests/test_data_objects.py` | `All checks passed!` |
| 阶段 4 用例 | `pytest backend/tests/test_data_objects.py backend/tests/test_probe_task_lifecycle.py -q` | 28 passed |
| 共享层回归 | `pytest backend/tests/shared -q` | 140 passed |

## 8. 已知限制与未验证项

- **未在真实探针上验证对象身份**：全部为进程内 + 隔离目录验证。真实主机上的同 Hash 跨主机聚合、改名与 sweep 端到端验收在阶段 5/6 进行。
- **部分指纹的候选聚合口径只在服务层实现**：`partial_fingerprint` 候选副本单独计数，但尚未在真实大文件上做过"体积/耗时"验证。
- **`data_objects` 的 `instance_count` 包含历史实例**：`active_instance_count` 才表示"当前仍在观测中的实例"。页面必须显示两者，不能用单一数字。
- **未验证大规模数据量下的 `data_type_rows()`**：内部有 `MAX_SUMMARY_ROWS = 50_000` 上限，超限时返回 `truncated=True` 而不是静默截断；该上限本身未在真实规模上压测。
- **外键未设 `ON DELETE CASCADE`**：删除实例/对象会被数据库拒绝，删除必须走 `forget_probe()` 这类显式路径。这是刻意的"不静默级联删除证据"，但也意味着后续若新增删除入口必须显式处理。
- **`progress_percent()` 的百分比是估算**：按已处理文件数对 `max_files` 的比值给出，并在返回体 `estimated=True` 标注；不是精确进度。
