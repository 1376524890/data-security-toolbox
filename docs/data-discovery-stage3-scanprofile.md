# 阶段 3 实施记录：ScanProfile、共享 ScanBudget、采样解析与增量缓存

- 前置：`docs/data-discovery-3.3.1-baseline.md`（阶段 0）、`docs/data-discovery-stage1-shared-engine.md`（阶段 1）、`docs/data-discovery-stage2-ruleset.md`（阶段 2）。
- 基线版本：平台 2.7.0 / 探针 3.3.1；本阶段**不递增版本号**（版本号在阶段 6 统一提升）。
- 本记录中所有数字均为本机实测，命令与结果见第 7 节；未验证项目集中在第 8 节。
- 部署凭据（SSH、探针 token、数据库口令）不写入本记录、代码或日志；需要凭据的验证均在已授权会话内完成。

## 1. 阶段完成判定

阶段 3 的完成标准是：**扫描范围与资源消耗由共享预算统一下界，任何限制下都不发生无界读取；结构化解析器如实上报读取量、覆盖程度与终止原因；未变化的文件在不重读内容的前提下复用分析结果；Profile 可版本化配置并被任务快照固定，且不改变旧 config/TOML 的发行默认值**。逐条对照：

| 阶段 3 要求 | 实测证据 |
|---|---|
| 共享 ScanBudget，所有阶段共用一个计数器 | `shared/scanning/budget.py`：`ScanBudget`/`BudgetExceeded`/`DEFAULT_LIMITS`/`TERMINATION_*`；类型探测、Hash、采样、解析、目录遍历全部走同一个实例（`inspect_file`/`discover_data_assets`） |
| Full Hash / Partial Fingerprint | `shared/scanning/fingerprint.py`：`FULL_SHA256`/`PARTIAL_FINGERPRINT`/`PARTIAL_VERSION="1.0.0"`/`SAMPLE_POSITIONS=(0,0.25,0.5,0.75,1.0)`；读取前后比对 size/mtime，变化则 `stable=False, reason="changed_during_read"`，**不会**产出"稳定完整 Hash"的假结论 |
| LargeFileSampler | `shared/scanning/sampler.py`：5 个位置的有界块采样、行对齐、丢弃不完整尾行、`MAX_LINE_CHARS=8192`、utf-8-sig/gb18030 解码 |
| Magic/Text 探测 | `shared/scanning/magic.py`：`FileType`/`detect()`/`probe_head()`/`PROBE_BYTES=4096`；未知扩展名如 `.dat/.dump/.data/.customer` 若为文本进入 GenericTextParser，二进制不强制解码 |
| GenericTextParser | `shared/scanning/parsers/generic_text.py` |
| CSV/TSV 增量增强 | `parsers/csv_tsv.py`：保留 Header，头/中/尾三区域各 `REGION_BYTES=192 KiB`，引号与跨行字段由 `csv` 模块处理，无法安全恢复的区域在 `note` 中声明覆盖限制，半行不当完整记录 |
| JSON/JSONL 增量增强 | `parsers/json_like.py`：大 JSON **降级为 generic_text** 而不是解析片段（`degraded_to`）；JSONL 保留最后 N 条完整记录；整文件解析前先 `budget.clamp_read(size) >= size` 确认预算足够 |
| SQL/SQL.GZ | `parsers/sql.py`：头部 DDL + 中尾 INSERT 片段；`_parenthesised()` 深度扫描器处理嵌套括号；gzip 走受限流式解压，不为取尾部而无界解压 |
| 有界 XLSX streaming parser | `parsers/xlsx.py`：openpyxl `read_only=True`；解析前用 `inspect_container()` 校验 entry 数、解压总大小、压缩比、sharedStrings，超预算即 Partial |
| 每个 Parser 上报真实读取量/覆盖/终止原因 | `parsers/base.py::ParseResult`（`bytes_read`/`rows_read`/`coverage`/`termination_reason`/`degraded_to`/`note`）；`as_evidence()` 保证结构信息不含任何样本值 |
| 安全增量缓存，版本变化重新分析 | `shared/scanning/cache.py`：`key_for()` 绑定 path/device/inode/size/mtime_ns/engine_version/ruleset_version/config_fingerprint；`CACHE_VERSION="1.0.0"`；损坏或撕裂行按 miss 处理且不抛出 |
| 元数据未变且分析条件一致时不读文件内容 | 命中即直接返回，`evidence.cached=True`（`test_a_second_scan_of_an_unchanged_file_is_served_from_the_cache`） |
| Profile 模型/API 及任务快照 | `backend/app/models.py::ScanProfile`（32 列）+ `0011_scan_profiles.py` + `services/scan_profile_service.py` + `api/profiles.py`；任务把解析后的配置复制进 `payload.profile_snapshot` |
| 兼容旧 config/TOML | `POST /api/v1/probes/{probe_id}/data-assets/jobs` 仍接受显式 `paths`/`max_files`/`max_depth`/`timeout_seconds`，且显式值优先于 profile；`[data]` 段新增键全部有默认值，旧 TOML 不需要改 |
| 发行默认不启用远程或定时扫描 | `DEFAULT_CONFIG["data"] = {enabled: False, allow_remote: False}`，`ScanProfile.enabled=True` 仅表示"可用于建任务"，`scheduled=False` 且默认 `interval_seconds` 不生效（探针侧 `[data].enabled=False`） |
| 测试：文件各位置敏感值、编码/行边界/重复区间、JSON 片段降级、XLSX sharedStrings/压缩攻击/超预算、空/损坏/变动文件/符号链接、缓存命中/规则失效、Hash 上限、部分指纹区别完整一致、取消检查点 | 阶段 3 新增 **116** 个用例（见第 6 节），全部通过 |

## 2. 数据模型与迁移

新增一张表（`backend/app/models.py`）：

| 表 | 关键列 | 说明 |
|---|---|---|
| `scan_profiles` | `name`(唯一)、`version`、`description`、`include_paths`/`exclude_paths`/`file_types`(JSON)、18 个数值预算列、`large_file_sampling`、`enabled`、`scheduled`、`interval_seconds`、`created_by`、`created_at`、`updated_at` | 版本化扫描配置；`UNIQUE(name, version)` |
| 索引 | `ix_scan_profiles_name`、`uq_scan_profile_version`、`scan_profiles_pkey` | — |

`backend/alembic/versions/0011_scan_profiles.py`（`down_revision=0010_rule_sets`）为纯增量迁移：只 `CREATE TABLE` 与建索引，不 drop、不修改既有列、不触碰旧业务数据。`upgrade()` 顶部有 `_table_exists()` 守卫，因此全新库路径与"库停在 0010"的生产路径走同一条分支。

### 2.1 任务快照语义

`queue_probe_data_asset_job(db, probe_id, config, *, profile=None)` 把解析后的配置**复制**进 `Task.payload`：

- `payload.config` 是探针实际执行的 scope；
- `payload.profile_id` 保留为顶层键（可被引用守卫直接查询）；
- `payload.profile_snapshot` 记录 `profile_id/profile_name/profile_version/config`。

这样"任务登记后编辑 Profile"不会改变探针被要求执行的内容；`profile_version` 让报告能回溯到当时的配置版本。探针侧 `discover_data_assets` 只读取它认识的键；快照里始终保留完整配置，避免平台假装已经执行了它没有执行的过滤。阶段 3 当时 `exclude_paths`/`file_types` 尚未被探针执行，**该限制已在 v2.8.0（探针 3.4.0）解除**，见第 9 节修订 R1。

## 3. 共享扫描层（`shared/scanning/`）

| 模块 | 职责 |
|---|---|
| `budget.py` | `ScanBudget`（单一计数器）、`BudgetExceeded`、`DEFAULT_LIMITS`、`TERMINATION_*`、`remaining_bytes()`、`clamp_read()`、`spend_bytes/rows`、`note_file/directory/skip`、`stop()`、`mark_truncated()`、`coverage()` |
| `fingerprint.py` | `identify()` / `full_sha256()` / `partial_fingerprint()` / `block_layout()` |
| `sampler.py` | `sample_text()` / `decode()` |
| `magic.py` | 扩展名 + 有界 Magic/文本探测 |
| `cache.py` | `AnalysisCache`（SQLite）、`config_fingerprint()`、`key_for()`、`CacheStats.as_evidence()`、`purge_missing()`、容量上限 |
| `parsers/` | `base.py`（`ParseResult`/`SheetSample`/`ColumnSample`/`infer_type`）、`generic_text.py`、`csv_tsv.py`、`json_like.py`、`sql.py`、`xlsx.py`、`parse_file()` |

发行默认预算（`DEFAULT_LIMITS`，同时是 `probe.toml.example` 的注释值）：

| 键 | 默认值 | 键 | 默认值 |
|---|---|---|---|
| `max_files` | 200（上限 2000） | `sample_block_size` | 64 KiB |
| `max_depth` | 3（上限 8） | `max_sample_rows` | 25 |
| `max_dirs` | 500 | `max_full_hash_size` | 8 MiB |
| `max_runtime_seconds` | 120（上限 1800） | `xlsx_max_rows` | 200 |
| `max_single_file_size` | 2 MiB | `xlsx_max_entries` | 512 |
| `max_bytes_read` | 512 MiB | `xlsx_max_uncompressed_bytes` | 64 MiB |
| `max_cpu_seconds` / `max_rss_mb` | 0（关闭） | `xlsx_max_compression_ratio` | 200.0 |

与主提示词/阶段的约定值逐项一致：200 文件（上限 2000）、深度 3（上限 8）、500 目录、2 MiB 内容样本、25 行、120 s、8 MiB 完整 Hash 上限。

## 4. 修复的真实缺陷

阶段 3 实现过程中发现并修复了 7 个**会产生错误结论或错误行为**的问题，全部有回归用例：

1. **预算耗尽却上报 `complete`（最严重）**。`ScanBudget.check()` 原来直接 `raise BudgetExceeded`，没有把原因写进计数器；调用方捕获后 `coverage()` 仍返回 `termination_reason="complete"`，于是"120 秒超时被打断的扫描"会满足 `complete_scope`，进而允许把该 Scope 内未出现的实例标为 `NOT_OBSERVED` —— 等于**用一次超时宣布真实数据已经消失**。现改为 `check()` 先 `stop(reason, detail)` 再抛出；`test_an_aborted_scan_never_reports_a_complete_scope`。
2. **`fingerprint.py` 抛裸 `BudgetExceeded`**：绕过了统一收口，reason 取默认值。现统一调用 `budget.check()`。
3. **`sampler.py` 超预算读取**：`handle.read()` 的返回值没有再次受 `remaining_bytes()` 约束，单次采样可以越过字节预算。现改用 `budget.clamp_read()`。
4. **CSV/TSV 尾部区域取错记录**：`_records()` 只保留**前** N 条，于是"尾部区域"实际采到的是该区域开头的数据，头/中/尾退化为头/中/中。新增 `from_tail=True`，尾区取 `rows[-limit:]`。
5. **大 JSON 解析片段当完整对象**：超过整文件阈值时原来退回按偏移解析，得到的是语法不完整的 JSON。现统一 `_degrade()` 到 `generic_text` 并置 `degraded_to`/`coverage=partial`，如实声明结构覆盖范围。
6. **SQL DDL 嵌套括号截断列名**：原正则遇 `varchar(20)` 会在第一个 `)` 处收尾，列名被截断。改为 `_parenthesised()` 深度扫描器。
7. **探针 `[data]` 配置未接线（本次会话修复）**：`discover_data_assets` 已经在读 `max_dirs`/`max_bytes_read`/`max_full_hash_size`/`xlsx_*`/`cache_path`，但 `probe.py::DEFAULT_CONFIG["data"]` 没有这些键，`probe.toml.example` 也没有文档化，且 `cache_path` 指向的目录不在 systemd `ReadWritePaths` 中 —— 真实主机上缓存会静默失效。现补齐默认值（直接取自 `shared.scanning.budget.DEFAULT_LIMITS`，不复制第二份）、文档化全部键、新增 `CACHE_DIR`，并把 `install.sh` 的复制清单加入 `shared/scanning`（缺它则扫描任务在 import 阶段就失败）。

## 5. 探针接线与打包

- `probe/probe.py`：新增 `_scan_budget_defaults()`，从 `shared.scanning.budget.DEFAULT_LIMITS` 直接生成 `[data]` 的预算默认值，`SCAN_BUDGET_KEYS` 显式列出键名，避免探针、平台、文档三份默认值漂移；`_run_data_asset_job` 增加 `merged['ruleset_version'] = self.ruleset.snapshot_version()`，使缓存键绑定本次任务固定的规则版本（这也是"规则更新触发有限重读"的实现点）。
- `probe/probe.toml.example`：`[data]` 段补齐全部预算键与 `cache_enabled`/`cache_path`，每个限制写明语义。
- `probe/install.sh`：新增 `CACHE_DIR=/var/lib/data-security-toolbox/cache`，创建/chown/chmod 0700，加入 systemd `ReadWritePaths`；`shared/scanning` 与 `shared/sensitive_detection` 一起复制，缺失即安装失败；复制后清理 `__pycache__`。
- `probe_packages/build_packages.py`：`TREES = {ROOT / "shared": "shared"}` 递归复制全部 `shared/**.py`，因此 `shared/scanning` 自动进入 amd64/arm64 包；已重新构建并核对 `manifest.json`（32 个文件，其中 `shared/scanning/**` 13 个，无 `__pycache__`）。

## 6. 测试

| 文件 | 用例数 | 覆盖 |
|---|---|---|
| `backend/tests/shared/test_scanning_core.py`（新增） | 40 | 预算计数/上限/终止原因；**中断的扫描不得上报 complete**；文件/目录/跳过计数；`clamp_read` 与剩余字节；完整 SHA256；读取期间变化不得报稳定；部分指纹块布局不重叠且被边界裁剪；采样 5 个位置、行对齐、丢尾行、编码；Magic 探测（文本/表格/压缩/XLSX/SQL.GZ/二进制/未知扩展名）；缓存命中/未命中/规则版本失效/配置指纹/损坏库/torn 行/容量上限；缓存内容不含原值 |
| `backend/tests/shared/test_scanning_parsers.py`（新增） | 34 | 空文件/单行/无尾换行；CSV 引号内换行、自定义分隔符、**尾部区域取最后记录**、半行不成记录、区域读取受预算约束；JSON 整文件、JSONL 保留最后 N 条、**大 JSON 降级**且置 `degraded_to`；SQL 嵌套括号 DDL 列名、中尾 INSERT、SQL.GZ 流式上限、损坏 gzip；XLSX 表头/列推断、行数超限、**ZIP 压缩比攻击**、entry 数超限、解压总量超限、sharedStrings 超限、畸形 XML、`as_evidence()` 不含样本值 |
| `backend/tests/probe/test_data_assets_scanning.py`（新增） | 15 | `inspect_file` 在预算内产出结构 + Detection 计数；超限文件标记 `partial`；符号链接不跟随；`discover_data_assets` 的 `coverage`/`termination_reason`；缓存二次扫描生效且不重读；规则版本变化触发重读；取消检查点；报告不含任何样本值 |
| `backend/tests/test_scan_profiles.py`（新增） | 27 | 默认值等于 `DEFAULT_LIMITS`；越界值被拒绝而非裁剪；列表/布尔字段校验；CRUD；`enabled`/`scheduled` 不改变探针发行默认；`run` 生成任务并写入 `profile_snapshot`；编辑 Profile 不改变已登记任务的快照；显式 `paths` 覆盖 profile；旧探针版本 409；探针已有活动任务 409；排序/分页白名单 |
| `backend/tests/shared/test_distribution.py`（扩展） | +2 | 包 manifest 必须列出 `shared/scanning/{budget,fingerprint,sampler,magic,cache,parsers/*}.py`；`install.sh` 必须复制 `shared/scanning`、必须有 `CACHE_DIR` 且进入 `ReadWritePaths`；`probe.toml.example` 必须含 `max_full_hash_size`/`xlsx_max_rows`/`cache_path`；**探针 `[data]` 默认值必须逐键等于共享包默认值**，且不得出现 TOML 里不存在的 `max_runtime_seconds` 键 |
| `backend/tests/shared/test_engine_wiring.py`（更新） | 10 | 改用 `inspect_file(sample, ScanBudget())` 签名 |
| `backend/tests/probe/test_data_assets.py`（更新） | 7 | 适配新的 `inspect_file`/`parse_file`/`ScanBudget` 契约 |

阶段 3 相关合计 **232 collected / 231 passed**（`shared` 122 + 探针 62 + `test_scan_profiles.py` 27 + 探针数据资产 7 等）。唯一失败是**环境性**的 `backend/tests/probe/test_probe_identity.py::test_first_registration_persists_identity`（Windows 上 `chmod 0o600` 无效，平台为 `438`），阶段 0 基线已记录，不属于业务缺陷。

## 7. 本次实测命令与结果

| 验证项 | 命令 | 结果 |
|---|---|---|
| 迁移（生产路径 0010→0011） | 容器内 `alembic upgrade 0010_rule_sets` → `alembic upgrade head`（scratch 库 `dst_mig3`） | 成功，`0011_scan_profiles (head)` |
| 迁移幂等 | 再次 `alembic upgrade head` | 无操作，仍为 head |
| 迁移往返 | `alembic downgrade 0010_rule_sets` → `upgrade head` | 成功往返，回到 `0011_scan_profiles (head)` |
| 全新库路径 | 空库 `alembic upgrade head` | 成功（0001 建表 + 0011 守卫跳过） |
| 表结构 | `information_schema.columns where table_name='scan_profiles'` | 32 列，含 `max_bytes_read`(bigint)/`max_cpu_seconds`(double precision)/`include_paths`(json) |
| 索引 | `pg_indexes where tablename='scan_profiles'` | `scan_profiles_pkey`、`ix_scan_profiles_name`、`uq_scan_profile_version` |
| 迁移破坏性语句 | `grep -iE "drop_table|drop_column|TRUNCATE" alembic/versions/0011_scan_profiles.py` | 仅 `downgrade()` 内的 `op.drop_table("scan_profiles")` |
| 探针包构建 | `python probe_packages/build_packages.py` | amd64 `sha256=3905c9e371c7322e139283498753127b13c1be79081e92d652a3c0151d4e973d`、arm64 `sha256=2c5fbe892ab09f948f921f44840cb7ff3e28f8fbad10920ab9025cbce0aa1973`；manifest 32 个文件，含 `shared/scanning/**` 13 个，无 `__pycache__` |
| 静态检查（新增代码） | `ruff check --select E9,F,B shared/scanning shared/sensitive_detection probe backend/app/services/scan_profile_service.py backend/app/api/profiles.py` | `All checks passed`（`profiles.py` 的 `B008` 是 FastAPI `Depends` 既有惯例，与全库一致） |
| 阶段 3 用例 | `pytest backend/tests/shared backend/tests/probe backend/tests/test_scan_profiles.py -q` | 232 collected / 231 passed / 1 known-env failed |

## 8. 已知限制与未验证项

- **未在真实主机上跑过 XLSX/大文件扫描**：本阶段全部为进程内 + 隔离目录验证；真实 Kali 探针上的合成 XLSX 端到端验收在阶段 5/6 进行。
- **未在真实探针上验证 systemd `ReadWritePaths` 生效**：`CACHE_DIR` 的创建与授权由 `install.sh` 断言（单测覆盖），实际 cgroup 写权限在阶段 6 升级后确认。
- ~~**`exclude_paths` / `file_types` 尚未被探针执行**~~：该限制在阶段 5 已被修复，探针现在真实执行两项过滤并回传 `coverage.scope_filter`。原文保留见第 9 节修订 R1。
- **部分指纹只能形成"疑似副本"**：`PARTIAL_FINGERPRINT` 版本为 `1.0.0`，相同指纹只代表候选，不能与完整 SHA256 的"内容一致"混入同一统计口径；聚合口径在阶段 4 实现。
- **XLSX `read_only` 不等于严格内存有界**：openpyxl 的 sharedStrings 仍需整体载入，因此用 `xlsx_max_shared_strings`/`xlsx_max_uncompressed_bytes` 显式设限，超限即 Partial 而非继续解析。
- **缓存键依赖 mtime_ns/size/inode，不是强完整性监控**：内容被替换但元数据完全一致的伪装变更不会被发现；这是已知能力边界，主提示词要求的"按配置周期强制重检"尚未提供开关。
- **`max_cpu_seconds` / `max_rss_mb` 默认关闭**：探针侧不主动采样自身资源，只有在配置里显式设置时才生效；默认 0 表示关闭而非"无限制即安全"。
- **阶段 3 未提供 Profile 管理界面**：阶段 3 的分阶段要求未包含前端交付，Profile/任务/进度页面按分阶段提示词在阶段 5 交付。

## 9. 修订记录（阶段 5 引入）

本节只记录对上面阶段 3 结论的**更正**，不改写阶段 3 当时的实测记录。

### R1. `exclude_paths` / `file_types` 已由探针真实执行

阶段 3 交付时这两项只进了 Profile 模型与任务快照，"尚未生效"是当时的真实状态。阶段 5 的端到端验收把这条列为必须闭环的缺口，因此补齐如下：

| 位置 | 变化 |
|---|---|
| `probe/data_assets.py` | 新增 `class ScopeFilter`、`scope_filter_for()`，接入 `discover_data_assets` 的目录遍历；被排除的目录不再进入遍历，`file_types` 变成扩展名允许列表 |
| `probe/data_assets.py` | 报告新增 `coverage.scope_filter`：回传生效的 `exclude_paths`/`file_types`、`excluded_directories`、`filtered_files` 计数 |
| `backend/app/services/scan_profile_service.py` | `probe_config()` 把 Profile 的 `exclude_paths`/`file_types` 翻译成探针配置 |
| `backend/app/api/extensions.py` | `DataAssetScanConfig` 接受这两个字段，并校验路径不含 `..` |
| `probe/probe.py`、`probe.toml.example`、`deployment/service.py` | `DEFAULT_CONFIG['data']` 与 toml 生成同步声明，保证"只声明不执行"不会再出现 |

被排除路径的语义（容易写错，已在单测中钉死）：

- 被排除的目录**仍然在扫描范围内**，只是不再被遍历/上报。因此一次**完整**扫描如果不再报告它，平台必须把它退化为 `NOT_OBSERVED`；
- 反过来，如果让 `in_scope()` 也跳过被排除路径，被排除的实例会永久停留在 `ACTIVE`，与"完整扫描才作结论"的语义冲突。所以 `in_scope()` **刻意忽略**排除项，由 `test_scope_test_ignores_exclusions_by_design` 固化这一决定。

### R2. 部分指纹摘要进入报告

`Fingerprint.as_evidence()` 原先不输出 `value`，导致 `resolve_identity()` 对大文件永远退化成 `hash_type='scoped'`，"疑似副本（partial）"这条候选路径在真实链路里从未被走到。v2.8.0 让摘要带上 `value` 与 `is_full`，探针再补 `partial` 标记；同时 `data_object_service` 只接受 `^[0-9a-f]{32,64}$` 的摘要，避免脱敏占位符变成对象键。

### R3. `recount_object` 漏算本轮扫到的实例

会话是 `autoflush=False`，`sweep_scope()` 刚改完的实例状态对随后的 `COUNT` 查询不可见，导致对象会多认领原本已消失的副本，直到下一份报告才纠正。修法是在 recount 之前 `if swept: db.flush()`。

### R4. 版本与包

阶段 3 记录里的 `3905c9e3…`/`2c5fbe89…` 是 3.3.1 的探针包摘要，已被 3.4.0 取代（amd64 `26a6544b…`、arm64 `d994d1ec…`）。平台 2.8.0 / 探针 3.4.0 的发布与升级记录见 `docs/data-discovery-stage6-upgrade.md`。
