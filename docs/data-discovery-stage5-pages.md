# 阶段 5 实施记录：P0 页面与真实端到端验收

- 前置：`docs/data-discovery-3.3.1-baseline.md`（阶段 0）、`-stage1-shared-engine.md`、`-stage2-ruleset.md`、`-stage3-scanprofile.md`、`-stage4-objects.md`。
- 版本：本阶段的代码即 v2.8.0（平台 2.8.0 / 探针 3.4.0）；版本号提升、镜像构建与现场升级记录见 `docs/data-discovery-stage6-upgrade.md`。
- 本记录中的数字全部来自**本机实测**：现场 PostgreSQL、平台 API、真实 Kali 探针与合成数据目录。没有估计值，也没有"低资源"这类无环境说明的形容词。
- 部署凭据（SSH、探针 token、数据库口令、平台管理员口令）不写入本记录、代码或日志；需要凭据的验证只在已授权会话内执行，摘要一律不包含 token 原文。

## 0. 这次验收的边界（先说清楚没做什么）

用户明确指示：**不做完整的端到端测试，代码跑通、推送、把最新版本跑起来，由用户手动测试**。
因此本记录是"分阶段的真实验收 + 明确的未执行清单"，不是"全绿通过报告"：

- 主提示词第 13 节要求的完整 E2E（含浏览器点击级操作、20 副本规模案例）**没有全部执行**；
- 已执行的部分逐项列在第 3、5 节，未执行的部分逐项列在第 7 节；
- 阶段 0-4 已交付并通过的单元/集成测试不受影响，见各阶段记录。

## 1. 阶段完成判定

| 阶段 5 要求 | 实测证据 |
|---|---|
| 数据类型中心/详情 | `frontend/src/modules/data-security/DataTypeCenter.vue`、`DataTypeDetail.vue`；路由 `/data-types`、`/data-types/:category`；真实接口 `GET /data-types`、`GET /data-types/{category}`，实测返回 7 个类别（`address/bank_card/credential/email/id_card/name/phone`） |
| 对象详情 | `DataObjectDetail.vue`；路由 `/data-objects/:id`；`GET /data-objects/{id}`、`GET /data-objects/{id}/detections` |
| 实例详情 | `AssetInstanceDetail.vue`；`GET /asset-instances/{id}` + `GET /detections/{id}/evidence`（证据单独取，列表页不夹带证据） |
| Profile/任务/规则版本入口 | `ScanProfiles.vue`（`/scan-profiles`）、`DataAssetJobs.vue`（`/data-asset-jobs`）、`RuleVersions.vue`（`/rule-versions`） |
| 保留旧页面与路由 | `/data/assets` 旧投影仍在服务：`GET /data/assets` 实测 `total=37`，行里仍带 source probe 与 path |
| 使用真实 API、权限、分页和状态 | 全部页面走 `frontend/src/api/{dataCatalog,scanProfiles,ruleSets}.ts`；无 mock 数据；分页用真实 `total` |
| 明确确认副本/疑似副本 | `DataTypeCenter` 的"确认副本"按完整 SHA256 聚合、`max(active_instance_count - 1, 0)` 求和；"疑似副本"用 `candidate_count` 单独成列，不并入确认副本 |
| 明确区分完整/部分扫描 | `DataAssetJobs.vue` 在 `coverage.complete_scope === false` 时显示"范围未完整覆盖"，并注明"不会标记数据消失" |
| 明确区分级别与旧严重度 | `GET /sensitivity-levels` 同时给出 `L1..L4`（来源 `builtin_default`）与派生旧词表 `Critical/High/Medium/Low` 的映射 |
| 旧探针能力不足时如实展示 | `RuleVersions.vue` 按探针上报的 `capabilities.ruleset_hot_update` 显示"支持/不支持"，未上报显示"未上报" |
| P1 风险/网络关系如实展示 | `DataTypeDetail.vue`、`DataObjectDetail.vue`、`AssetInstanceDetail.vue`、`DataAssetJobs.vue` 四处均渲染"尚未接入（P1）"占位卡片，不伪造连线、不伪造业务系统归属 |
| 真实前后端闭环 | 第 3 节 S1-S12，真实探针 + 合成 XLSX/CSV/JSONL/SQL/大文件 |
| 前端测试与类型检查 | 见第 5 节 |
| 源码/API 无原始敏感值外传 | 第 4 节；`shared/sensitive_detection/report_guard.py` + `backend/app/services/report_guard.py` + 页面级断言 |

## 2. 交付页面

| 路由 | 组件 | 使用的真实接口 | 关键交互 |
|---|---|---|---|
| `/data-types` | `DataTypeCenter.vue` | `GET /data-types` | 类别卡片、对象/主机/确认副本/疑似副本口径说明 |
| `/data-types/:category` | `DataTypeDetail.vue` | `GET /data-types/{category}` | 分页表格、`identity_kind` 徽标、截断提示 |
| `/data-objects/:id` | `DataObjectDetail.vue` | `GET /data-objects/{id}`、`/detections` | 对象身份（`identity_kind` 为 `candidate` 时显示"疑似副本（部分指纹相同，需人工确认）"）、实例列表、检测分页 |
| `/asset-instances/:id` | `AssetInstanceDetail.vue` | `GET /asset-instances/{id}`、`GET /detections/{id}/evidence` | 身份/属性/覆盖/检测、证据抽屉（sheet、列、字段名，无原值）、"尚未接入（P1）" |
| `/scan-profiles` | `ScanProfiles.vue` | `GET/POST/PUT/DELETE /scan-profiles` | 列表分页、启停、版本化编辑、探针选择 |
| `/data-asset-jobs` | `DataAssetJobs.vue` | `GET /tasks?kind=data_asset_scan`、`POST /probes/{id}/data-assets/jobs`、`POST /tasks/{id}/stop` | 下发、进度、`coverage` 展开、取消、Partial/Failed 提示 |
| `/rule-versions` | `RuleVersions.vue` | `GET /rulesets`、`/rules`, `/versions`, `POST /versions`, `POST /rollback` | 版本列表、发布、回滚、按探针显示热更新能力 |

页面共同点：分页使用接口返回的 `total`；空态、错误态都有独立分支；详情页都可从列表行跳转。

## 3. 真实端到端验收

### 3.1 合成数据与 Profile

探针侧合成目录 `/srv/dst-e2e`（`dstprobe` 可读）：`客户信息.xlsx`、`contacts.csv`、`customers.jsonl`、`dump.sql`、`readme.md`、`notes.txt`、`large_report.bin`（64 MiB）、`archive.zip`、`nested/a/b/depth3.csv`、`nested/a/b/c/depth4.csv`、`skipme/should_not_appear.csv`。

Profile：`id=3`、`name=e2e-合成数据目录`、`version=3`、`include_paths=["/srv/dst-e2e"]`、`exclude_paths=["/srv/dst-e2e/skipme"]`、`max_files=200`、`max_depth=3`。

### 3.2 验收窗口与结果

S1-S8 与 S10-S12 在真实探针上执行（S10 的热更新在本次会话中观察到探针完成下载与应用）：

| 窗口 | 断言 | 结果 | 证据 |
|---|---|---|---|
| S1 | 探针在线、基线规则集已发布 | 通过 | `probes.id=1 status=online`、`agent_version=3.4.0`；`builtin-1` 146 条、`sha256=62cc3c1c…` |
| S2 | Profile 创建 → 下发 → Pending/Running/Success → 进度 100 → schema 1.1 → 范围完整 | 通过 | task 546：`Success`、`progress=100`、`schema_version=1.1`、`complete_scope=true` |
| S2 | `exclude_paths` 被探针真实执行 | 通过 | task 576/578/581/583/587/630 的 `coverage.scope_filter.excluded_directories=1`；被排除目录从未进入报告 |
| S3 | 数据类型/对象/级别/实例/详情/证据可查 | 通过 | 见第 4 节 15/15 只读复核 |
| S3 | XLSX 本地解析并给出 sheet/列证据 | 通过 | 实例 9 的证据含 `sheet_name=客户信息 / 订单信息`、`field_name=身份证号/手机号/姓名/地址`，无原值 |
| S3 | 大文件是"疑似副本"而不是确认副本 | 通过 | `object_key=partial:1.0.0:…`、`hash_type=partial_fingerprint`、`identity_kind=candidate`、`identity_confidence=0.5`、`content_hash=""`，`size=67108910` |
| S3 | 深度 3 生效（depth4 不出现） | 通过 | 报告中只有 `nested/a/b/depth3.csv` |
| S3 | 被排除路径被**退役**而不是冻结 | 通过 | 排除目录下的实例为 `NOT_OBSERVED`，没有一条留在 `ACTIVE` |
| S3 | 分页、状态过滤、详情跳转 | 通过 | `ACTIVE=28`、`NOT_OBSERVED=4`，分页参数被真实消费 |
| S4 | 无变化增量：复用缓存、零重复读取 | 通过 | task 576：`cache.hits=10, misses=0, bytes_read=0`，对象数不变 |
| S5 | 改名后的 Scope 生命周期 | 通过 | task 578：旧路径 `NOT_OBSERVED`、新路径 `ACTIVE`、仍指向同一个 `object_id`（`active_instance_count=1`） |
| S6 | 删除后被清退 | 通过 | task 579：`not_observed=1`，被删文件转 `NOT_OBSERVED` |
| S7 | 预算截断如实报 Partial | 通过 | task 583：`status=Partial`、`termination_reason=file_budget`、`complete_scope=false` |
| S8 | 不可读根目录报失败，而不是静默成功 | 通过 | task 585：`Failed` |
| S8 | 失败后重试成功 | 通过 | task 587：`Success`、`complete_scope=true` |
| S9 | 运行中的任务可取消 | 通过（本次补做） | task 628（`/usr`，`max_files=2000`）：`Running` 后取消 → `status=Cancelled`，探针服务 `ActiveEnterTimestamp` 前后一致 |
| S9 | 取消不重启探针、不声称范围完整 | 通过 | `probe.service` 启动时间 `2026-09-16 03:34:58 EDT` 全程未变；被取消任务无 `complete_scope` |
| S10 | 新规则集版本发布并列出 | 通过 | `e2e-hot-2`、147 条（基线 146 + 1 条验收标记规则）、`sha256=5a6713dc…` |
| S10 | 探针**不重启**应用新规则 | 通过 | 探针 `rules/state.json`：`version=e2e-hot-2`、`source=server`、`updated_count=1`、`last_error=""`；服务启动时间未变；`rules/current/ruleset.json` 内含新规则 |
| S10 | 后续任务使用新规则版本 | 通过 | task 630：`ruleset_version=e2e-hot-2` |
| S11 | 规则集回滚可用 | 通过（语义见下） | `POST /rulesets/1/rollback{to_version:builtin-1}` → 派生新版本 `builtin-1.rollback`，`rule_count=146`，包内 `rules` 与 `builtin-1` 逐条一致 |
| S12 | 旧 `/data/assets` 不回归 | 通过 | `total=37`，行内保留 source probe 与 path |

**关于 S11 的准确语义**：回滚**不会**把 `builtin-1` 重新设为 active，而是从目标版本派生并发布一个新版本 `builtin-1.rollback` 再激活它。逐字节比对两份规则包（`rule_set_versions.package`）：

```
pack sizes: 56938 / 56947
  DIFF created_at
  DIFF ruleset_version
  SAME engine_version / min_agent_version / rules / schema_version
rules: 146 146 identical: True
```

即 `rules` 数组完全一致（146 条、无差异），`sha256` 不同仅仅因为包内 `ruleset_version` 与 `created_at` 变了。这是"内容等价、身份新增"的回滚，而不是指针切回旧版本——这一点必须写清楚，否则会误判成"回滚失败"。

**两处断言写错，必须记录，否则会被误读成功能失败：**

1. 驱动脚本最初断言"active 应该变回 `builtin-1`"，于是记成 FAIL。实际行为是派生 `builtin-1.rollback`——功能正确，断言错。
2. "回滚在探针侧生效"的等待窗口最初只给了 360 秒，而探针的规则轮询周期是 900 秒，所以第一次没等到。改用 700 秒窗口复验后通过：

```
[PASS] S11 the rollback reaches the probe on its next poll
       probe_state={"version": "builtin-1.rollback2", "sha256": "2d2784ca9b9e15b2…", "rule_count": 146,
                    "source": "server", "loaded_at": "2026-09-16T08:05:02Z", "updated_count": 2}
       waited=155s
[PASS] S11 the rollback needed no probe restart  03:34:58 EDT -> 03:34:58 EDT
[PASS] S11 the probe reports the rollback came from the server  source=server
```

也就是说：**规则热更新的发布、生效与回滚三条路径都在真实探针上跑通了，且全程没有重启服务。**

回滚链最终状态：active = `builtin-1.rollback2`（146 条，内容等价于 `builtin-1`），探针已收敛到同一版本（`updated_count=2`）。

### 3.3 任务级覆盖证据（现场库直读）

| task | 状态 | files_analyzed | bytes_read | termination | complete_scope | cache 命中/未命中 | not_observed | 排除目录 |
|---|---|---|---|---|---|---|---|---|
| 546 | Success | 11 | 419825 | complete | true | 0 / 11 | 0 | – |
| 576 | Success | 10 | **0** | complete | true | **10 / 0** | 2 | 1 |
| 578 | Success | 10 | **0** | complete | true | 10 / 0 | 0 | 1 |
| 579 | Success | 10 | 6974 | complete | true | 9 / 1 | 1 | 1 |
| 581 | Success | 9 | 0 | complete | true | 9 / 0 | 1 | 1 |
| 583 | Partial | 4 | 0 | file_budget | false | 3 / 0 | 0 | 1 |
| 585 | Failed | 0 | 0 | – | – | 0 / 0 | 0 | – |
| 587 | Success | 9 | 0 | complete | true | 9 / 0 | 0 | 1 |
| 618 | Partial | 14 | 4391307 | row_budget | false | 0 / 14 | 0 | – |
| 628 | Cancelled | – | – | – | – | – | – | – |
| 630 | Success | 9 | 406569 | complete | true | 0 / 9 | 1 | 1 |

读法：576 这一行是"无变化增量"的硬证据——10 个文件全部命中缓存、**一个字节都没有重新读取**；579 只有 1 个文件未命中（就是被改动的那一个）。

## 4. 只读复核（15/15）

会话后期对现场栈做了一次只读复核（`%TEMP%\e2e-evidence.json`），15 项全通过：

- R1 探针在线、`agent_version=3.4.0`、能力协商含 `data_asset_scan` 与 `ruleset_hot_update`
- R2 数据类型中心列出 7 个类别；R3 响应不含任何原始匹配值
- R4 `L1..L4` 目录可用，来源 `builtin_default`
- R5 对象列表 `total=32`，`hash_type` 分布 `full_sha256=23 / scoped=7 / partial_fingerprint=2`
- R6 响应不含原始匹配值
- R7 两个候选对象都满足 `identity_kind=candidate`、`identity_confidence<1`、`content_hash` 为空
- R8 实例状态 `ACTIVE=28 / NOT_OBSERVED=4`；R9 响应不含原始匹配值
- R10 XLSX 实例 9 的证据来自本地解析：sheet `客户信息 / 订单信息`，字段 `身份证号 / 手机号 / 客户姓名 / 收货手机号 / 姓名 / 地址`
- R11 实例详情不含原始匹配值
- R12 对象详情列出 6 条检测；R13 不含原始匹配值
- R14 共享对象 `active_instance_count` 与实例数一致
- R15 旧 `/data/assets` 仍服务（`total=37`）

"不含原始匹配值"用的是与探针相同的针值集合（合成数据里的手机号/身份证号/银行卡号/姓名片段），在整份 JSON 响应文本上做子串匹配。

## 5. 前端验证

| 项目 | 命令 | 结果 |
|---|---|---|
| 单元测试 | `cd frontend && npm test` | 8 个文件 / **31 passed** |
| 类型检查 | `cd frontend && npm run typecheck`（`vue-tsc --noEmit`） | **无输出，退出码 0** |
| 生产构建 | 镜像构建内的 `vite build` | 通过；`source-frontend` 镜像 15:01 构建，晚于 `frontend/src` 全部改动 |
| 路由可达 | `GET /`、`/data-types`、`/scan-profiles`、`/data-asset-jobs`、`/data-types/id_card` | 全部 HTTP 200 |

**未执行**：浏览器点击级操作（登录、翻页、点开抽屉）。原因见第 0 节——用户明确接手手动测试，我不想在其正在使用的浏览器里插入自动化会话。这一项归类为"委派用户手动验收"，而不是"通过"。

## 6. 本阶段发现并修复的真实缺陷

四个缺陷都不是测试改写出来的，是端到端链路真实暴露的。详细修订说明见 `docs/data-discovery-stage3-scanprofile.md` 第 9 节：

1. **探针从不回传部分指纹摘要**：`Fingerprint.as_evidence()` 不输出 `value`，`resolve_identity()` 于是永远退化成 `scoped`，"疑似副本"这条候选路径在真实链路里是死代码。修复后大文件才真正产出 `partial:1.0.0:…`（第 3.2 节 S3 那行就是它生效的证据）。顺带把 `data_object_service` 的对象键收紧为只接受 `^[0-9a-f]{32,64}$`，杜绝脱敏占位符变成对象键。
2. **`recount_object` 漏算本轮扫到的实例**：会话 `autoflush=False`，`sweep_scope()` 刚写下的状态对随后的 `COUNT` 不可见，对象会多认领已消失的副本。修法是 recount 前 `if swept: db.flush()`。
3. **`queue_probe_data_asset_job` 硬编码"升级到 3.3.1"**：改为读 `settings.probe_agent_version`。
4. **`exclude_paths` / `file_types` 只存在于模型里**：探针从不执行。补齐 `ScopeFilter` / `scope_filter_for()`，并把生效范围回传到 `coverage.scope_filter`。

**一个被否掉的"修复"必须记下来**：中途曾让 `in_scope()` 也跳过被排除路径——这是错的。被排除路径仍在扫描树内，一次完整扫描如果不再报告它，就必须把它退役成 `NOT_OBSERVED`；跳过它反而会让这些实例永久停留在 `ACTIVE`。该改动已回滚，并由 `test_scope_test_ignores_exclusions_by_design` 把"`in_scope()` 刻意忽略排除项"钉成契约。

## 7. 未执行 / 未验证清单

诚实列出，避免"全绿"误解：

- **浏览器点击级验证**：未执行（用户接手手动测试）。
- **20 副本规模案例**：未执行。主提示词允许用隔离集成测试实现，本次连集成测试也没跑到该规模。
- **`arm64` 实机验证**：未做。探针包 `arm64` 只做了内容与 SHA256 校验，没有 arm64 实机，不能宣称实机通过。
- **探针侧 `systemd` 沙箱在真实写入压力下的行为**：只验证了 `ReadWritePaths` 覆盖 `cache` 目录且服务正常运行，没有做磁盘写满/权限收紧的破坏性演练。
- **阶段 5 初始验收运行没有留下完整报告文件**：早期那次 S1-S8 运行的驱动脚本在收尾前被中断，`e2e-report.json` 未落盘。本记录改用**现场库与 API 的只读复核**作为证据来源——这比一份日志更强，因为任何人可以在 UI 的"数据资产任务"页复核同样的行。执行过程中还发现原驱动的两处脚本缺陷（`max_files` 超出上限 2000 会 422；探针 `state.json` 的键是 `version` 而不是 `current_ruleset_version`），已在补做的脚本中修正。

## 8. 实测命令与结果

| 项目 | 命令 | 结果 |
|---|---|---|
| 共享/探针/Profile 用例 | `pytest backend/tests/shared backend/tests/probe backend/tests/test_scan_profiles.py -q` | 阶段 3 记录：232 collected / 231 passed / 1 known-env |
| 对象模型用例 | `pytest backend/tests/test_data_objects.py -q` | 29 passed |
| 规则集用例 | `pytest backend/tests/test_ruleset_release.py backend/tests/test_migration_0010_rule_sets.py -q` | 通过 |
| 全量回归 | `pytest -q` | 406 passed / 1 skipped / 5 failed（5 项均为 Windows 无 tshark、无 Redis 的环境问题，非业务缺陷） |
| 只读证据复核 | `python e2e_evidence2.py`（会话内脚本） | 15 / 15 |
| S9-S12 补做 | `python e2e_tail2.py`（会话内脚本） | 见第 3.2 节 |
| 前端 | `npm test` / `npm run typecheck` | 31 passed / 干净 |

## 9. 留给人工测试的现场状态

- 探针 `192.168.191.130` 的合成目录 `/srv/dst-e2e` 保持完整，`/srv/dst-e2e/skipme` 仍在，可直接复现"排除 + 深度 3 + 大文件疑似副本"。
- `scan_profiles.id=3`（`e2e-合成数据目录`，版本 3）可继续用来下发任务。
- `data_asset_scan` 任务 546 / 576 / 578 / 579 / 581 / 583 / 585 / 587 / 618 / 628 / 630 就是上面那张表的原始记录。
- 规则集版本历史里有 4 条：`builtin-1`(146) / `e2e-hot-2`(147，含验收标记规则) / `builtin-1.rollback`(146) / `builtin-1.rollback2`(146)，后三条是本次验收产生的。**当前 active = `builtin-1.rollback2`**，内容与 `builtin-1` 逐条一致；探针 `rules/state.json` 已收敛到同一版本。也就是说手工测试用的是干净的 146 条基线规则。
- 618（`/usr/share`）与 628（`/usr`）是本次验收新造的任务，属于验收残留数据；不再需要时可在"数据资产任务"页对照删除。

## 10. 已知限制与 P1/P2 边界

- **P1 未接入**：风险评分、网络来源证明、关系图谱、业务系统归属。四个页面对应位置显示"尚未接入（P1）"，不画假连线。数据模型（`GraphRelation` 等）边界已在阶段 0/4 记录中说明。
- **证据是元数据，不是内容**：`detection_evidence` 只有规则、识别器、字段名、sheet 名、列号、置信度与命中数，结构上不存在存值列。这是刻意的设计约束，不是缺失。
- **部分指纹只能形成候选**：`PARTIAL_VERSION=1.0.0`，相同指纹只代表"疑似"，永远不进"确认副本"统计。
- **缓存依赖 `mtime_ns`/`size`/`inode`**：元数据完全一致的伪装改动不会被发现；按配置强制重检的开关仍未提供。
- **XLSX 的 `read_only` 不等于内存严格有界**：sharedStrings 仍整体载入，因此用 `xlsx_max_shared_strings` / `xlsx_max_uncompressed_bytes` 显式设限，超限转 Partial 而非继续解析。
