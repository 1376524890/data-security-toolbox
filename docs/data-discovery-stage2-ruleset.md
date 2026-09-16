# 阶段 2 实施记录：中央 RuleSet、不可变发布与探针热更新

- 前置：`docs/data-discovery-3.3.1-baseline.md`（阶段 0）、`docs/data-discovery-stage1-shared-engine.md`（阶段 1）。
- 基线版本：平台 2.7.0 / 探针 3.3.1；本阶段**不递增版本号**（版本号在阶段 6 统一提升）。
- 本记录中所有数字均为本机实测，命令与结果见第 6 节；未验证项目集中在第 7 节。
- 部署凭据（SSH、探针 token、数据库口令）不写入本记录、代码或日志；需要凭据的验证均在已授权会话内完成。

## 1. 阶段完成判定

阶段 2 的完成标准是：**服务器是规则的唯一管理源，发布版本不可变且可追溯，探针在有界、校验、原子、可回退的前提下不重启完成热更新，并且失败不影响心跳/抓包/扫描**。逐条对照：

| 阶段 2 要求 | 实测证据 |
|---|---|
| 规则模型/迁移/发布/回滚 | `rule_sets`/`rules`/`rule_set_versions` 三表 + `0010_rule_sets.py`；PostgreSQL 16.6 上 0009→0010、重复执行、downgrade/upgrade 往返均已实测 |
| 发布版本不可变，回滚产生可追踪记录 | `publish()` 拒绝重名（HTTP 400）；`rollback()` 生成 `<v>.rollback` 新版本并记录 `origin_version`，原版本行内容不变（`test_rollback_republishes_old_bytes_as_a_new_traceable_version`） |
| Manifest 含版本/模式/引擎/min_agent/时间/SHA256/规则数/大小/下载定位 | `GET /api/v1/probes/{id}/ruleset/manifest`；SHA256 对**实际下载字节**校验（`test_probe_download_returns_the_exact_published_bytes` 比对响应体与响应头） |
| 旧 `/api/v1/dlp/rules` 入口继续工作 | `app/api/libraries.py` builtin 从共享包读取（阶段 1 已改）；新规则库不与旧入口分叉：`ruleset_service.import_working_rules()` 把旧托管规则导入同一工作副本 |
| 探针心跳附加 current_ruleset_version/capabilities，响应附加 latest_ruleset_version | `probe.py::heartbeat_once` 展开 `ruleset.status.to_dict()`；`POST /probes/{id}/heartbeat` 返回 `latest_ruleset_version`；旧探针不带新字段仍被正常应答（`test_a_legacy_probe_heartbeat_still_works_without_the_new_fields`） |
| 下载走已认证接口 + probe token，不跟随任意 URL | 两个探针端点均调用 `authenticated_probe`；`main.py::_is_probe_api` 仅豁免**管理端会话**检查，不豁免探针 token |
| 热更新：有界下载→Hash→Schema/版本→临时引擎→有界自测→原子发布 | `probe/ruleset_client.py::sync()`；失败记录原因并保留旧规则 |
| current/previous/staging 位于受限可写目录 | `RULES_DIR=/var/lib/data-security-toolbox/rules`（0700 dstprobe）加入 systemd `ReadWritePaths`；`install.sh` 创建并 chown |
| 运行中的任务固定快照，不在同一报告混用规则版本 | `_run_data_asset_job` 固定 `use_engine(self.ruleset.engine_snapshot())`，报告写入 `ruleset_version`/`engine_version` |
| 规则管理界面可见发布与同步结果 | `frontend/src/modules/data-security/RuleVersions.vue`（`/rule-versions`），展示发布记录与每台探针的实际同步状态/失败原因 |
| 测试：正确/错误 SHA256、畸形 Schema、超大包、恶意正则、版本不兼容、下载中断、缓存损坏、发布时并发扫描、回滚、旧探针心跳、新 API 认证与越权 | 阶段 2 新增/扩展 **52** 个用例（见第 5 节），全部通过 |

## 2. 数据模型与迁移

新增三张表（`backend/app/models.py`，插入位置在 `GraphRelation` 之前）：

| 表 | 关键列 | 说明 |
|---|---|---|
| `rule_sets` | `name`(唯一)、`description`、`active_version_id` | 规则集；`active_version_id` 指向当前生效发布版本 |
| `rules` | `rule_set_id`、`rule_id`、`entity`、`pattern`、`confidence`、`validator`、`field_hints`、`keywords`、`enabled`、`source` | **工作副本**，可编辑；`UNIQUE(rule_set_id, rule_id)` |
| `rule_set_versions` | `version`、`status`、`schema_version`、`engine_version`、`min_agent_version`、`sha256`、`rule_count`、`origin_version`、`changelog`、`published_by`、`manifest`、`package`(LargeBinary) | **不可变发布快照**；`package` 存放探针实际下载的字节；`UNIQUE(rule_set_id, version)` |

`backend/alembic/versions/0010_rule_sets.py`（`down_revision=0009_probe_data_assets`）为纯增量迁移，只建表/索引/外键，不 drop、不修改既有列。

### 2.1 迁移中修复的两个真实缺陷

1. **外键顺序（PostgreSQL 会直接失败）**。`rule_sets.active_version_id → rule_set_versions.id` 与 `rule_set_versions.rule_set_id → rule_sets.id` 互为引用。初版把前者的外键写成 `CREATE TABLE` 内联约束，而 `rule_set_versions` 尚未创建，PostgreSQL 拒绝（实测 `UndefinedTable: relation "rule_set_versions" does not exist`）。这正是**生产升级路径**（库停在 0009）唯一走的分支：只有在全新库上 `0001_initial` 的 `Base.metadata.create_all` 会按拓扑序先建 `rule_set_versions`，从而掩盖该问题。现改为最后用 `create_foreign_key` 单独添加，并在全新库/既有库两条路径上分别实测。
2. **downgrade 顺序**。原 `downgrade` 直接先 drop `rule_set_versions`，被 `rule_sets` 的外键阻挡。现按 `rules` → 解除 `rule_sets` 外键 → `rule_set_versions` → `rule_sets` 的顺序执行。

SQLite 不支持 `ALTER TABLE ADD CONSTRAINT`，而 SQLite 仅用于测试且其模式来自 `create_all`（内联输出该外键），因此该步在 SQLite 上跳过并在代码中注明原因。

## 3. 服务端：发布与解析

`backend/app/services/ruleset_service.py`：

- `build_pack(rules, version, min_agent_version, created_at)` —— **校验是真实的**：序列化后加载规则包并构建一次引擎，任何一条规则不可用（正则匹配空串、`MAX_PATTERN_CHARS` 超长、未知 validator、重复 `rule_id`）都会让整次发布失败，而不是静默丢弃。全部规则禁用、规则集为空、超过 `MAX_RULES_PER_PACK=2000`、包体超过 `MAX_PACK_BYTES=2 MiB` 同样拒绝。
- `publish()` —— 版本名符合 `VERSION_PATTERN` 才接受；同名版本拒绝；发布后把同规则集其他 `published` 版本置为 `superseded`，但**不删除**。
- `rollback(to_version)` —— 取历史版本的规则重新序列化为**新版本**（`<v>.rollback`，重复回滚则 `.rollback2`…），记录 `origin_version`。这里有意不做字节复制：包内嵌 `ruleset_version`，若沿用旧标签，探针上报的版本会与它下载的 manifest 无法对齐；历史行本身保持原字节不变。
- `ensure_baseline()` —— 幂等：导入工作副本（`builtin` 12 条 + 旧托管规则），若无生效版本则发布 `builtin-1`。重复调用不产生第二个基线版本。
- `version_manifest()` —— `sha256`/`rule_count` 来自发布行，`size` 取 `len(package)`，均为真实值，不用重新序列化的结果推算。
- `capabilities()` —— `{rulesets, schema_version, engine_version, max_pack_bytes, digest:"sha256"}`。

`backend/app/api/rulesets.py` 实际实现的路径（非建议路径）：

| 方法 | 路径 | 认证 |
|---|---|---|
| GET | `/api/v1/rulesets` | 管理端会话 |
| GET | `/api/v1/rulesets/{id}/rules` | 管理端会话 |
| POST | `/api/v1/rulesets/{id}/rules/import` | 管理端会话 |
| GET | `/api/v1/rulesets/{id}/versions` | 管理端会话 |
| POST | `/api/v1/rulesets/{id}/versions` | 管理端会话 |
| POST | `/api/v1/rulesets/{id}/rollback` | 管理端会话 |
| GET | `/api/v1/probes/{probe_id}/ruleset/manifest` | **probe token** |
| GET | `/api/v1/probes/{probe_id}/ruleset` | **probe token** |

`main.py::_is_probe_api` 只把这两个路径从"需要管理端会话"中豁免，`authenticated_probe` 仍然强制校验 `X-Probe-ID`/`X-Probe-Token`，并校验 probe_id 与令牌所属探针一致（跨探针读取返回 403）。

## 4. 探针：热更新与回退

`probe/ruleset_client.py::RuleSetClient` 的流程：

```
manifest → up_to_date 则跳过 → 有界下载 → SHA256 校验 → schema/engine/agent 版本检查
        → 构建临时引擎 → 有界自测 → 原子切换 → 写状态
```

- **目录布局**：`<rules dir>/{current,previous,staging}/ruleset.json` + `state.json`。切换是整目录 `os.replace`，不就地改写；`staging` 先写临时文件再 `fsync` + `os.replace`。
- **启动选择**：`load_usable()` 依次尝试 `current`、`previous`，都不可用才回退到随包内置快照（`build_local_pack`），并如实标 `ruleset_source=builtin`。探针**不会自行生成生产规则**。
- **拒绝条件**：摘要不匹配、JSON/结构非法、`engine_version[:2]` 与本地不兼容、`min_agent_version` 高于本机版本、manifest 声明大小超过 `max_pack_bytes`（下载前即拒绝）、自测超时或有规则超时、外部包中含匹配空串的规则、未知 validator、`regex` 后端不支持超时（此时直接拒绝外部包并上报原因）。
- **失败不致命**：`sync()` 永不抛异常，只记录 `last_error`；心跳/抓包/命令/报告重试线程继续运行。

### 4.1 修复的真实缺陷

`RuleSetClient._activate()` 原本会清空 `last_error`。这导致**缓存损坏后回退到 `previous` 的探针显示为完全健康**——损坏原因在运维界面上不可见，与"失败保留旧规则并上报失败原因"的要求相冲突。现改为：加载可用规则包不再清空错误，只有一次干净的服务端同步才清除。

### 4.2 探针配置与打包

- `probe/probe.py::DEFAULT_CONFIG["ruleset"]`：`enabled=True`、`dir=/var/lib/data-security-toolbox/rules`、`max_pack_bytes=2097152`、`self_test_timeout_seconds=2.0`、`poll_seconds=900`。热更新默认开启（服务器是唯一规则源），离线时用随包快照，因此默认值不构成离线风险。
- `probe/probe.toml.example` 增加 `[ruleset]` 段；`probe/install.sh` 的复制清单加入 `ruleset_client.py`。
- `probe_packages/build_packages.py` 的 `FILES` 加入 `ruleset_client.py`（**原来缺失**：包内没有该模块，`probe.py` 的 import 会在客户现场失败）。已重新构建 amd64/arm64 包并核对 `manifest.json`。

## 5. 测试

| 文件 | 用例数 | 覆盖 |
|---|---|---|
| `backend/tests/probe/test_ruleset_client.py`（新增） | 19 | 首次离线用内置快照；成功热更新不重启换规则且状态可跨进程恢复；已是最新则不重复下载；错误 SHA256；畸形 Schema；超大包（下载前拒绝）；`engine_version` 不兼容；`min_agent_version` 门控；下载中断；缓存损坏回退 `previous` 并保留原因；含空串匹配规则整体拒绝；未知 validator 拒绝；灾难性正则被超时约束（<5s 且上报 timeout）；无超时后端拒绝外部包；禁用时不访问服务器；manifest 缺版本；心跳字段含来源说明；被取代版本保留以便回退 |
| `backend/tests/test_ruleset_release.py`（新增） | 29 | 基线幂等；同版本重复发布拒绝；**编辑工作副本不改变已发布版本字节与摘要**；manifest 大小/版本真实；发布取代而不删除；能力自述；6 类不可用发布（版本名/空集/重复 ID/空串匹配/未知 validator/全禁用）；超上限包；字节可复现（固定 `created_at`）；**包内不含任何匹配值**；回滚可追溯且历史行不变；二次回滚独立命名；回滚未知版本拒绝；API 列表/发布/重复发布 400/回滚/非法版本 400；探针端点无凭据被拒、跨探针 403；下载字节与响应头摘要一致；`current` 命中时 `up_to_date`；`min_agent_version` 门控返回 409 且不降级；未知版本 404；旧探针心跳兼容；心跳返回 `latest_ruleset_version` |
| `backend/tests/test_migration_0010_rule_sets.py`（新增） | 4 | 迁移可重复执行并建齐三表；`rule_sets` 不含内联前向外键（即上述缺陷的回归保护）；downgrade 先解约束再删表；upgrade 不含任何破坏性语句 |
| `backend/tests/shared/test_distribution.py`（扩展） | +1 | 探针包 manifest 必须列出 `ruleset_client.py`，`install.sh` 必须复制它，`probe.toml.example` 必须含 `[ruleset]`/`max_pack_bytes`/可写目录 |

阶段 2 相关合计 **116 passed**（`shared` 64 + 探针客户端 19 + 服务端发布 29 + 迁移 4）。

## 6. 本次实测命令与结果

| 验证项 | 命令 | 结果 |
|---|---|---|
| 迁移（生产路径 0009→0010） | 容器内 `alembic upgrade head`（scratch 库 `dst_migration_check`） | 成功，`0010_rule_sets (head)` |
| 迁移幂等 | 再次 `alembic upgrade head` | 无操作，仍为 head |
| 迁移往返 | `alembic downgrade 0009_probe_data_assets` → `upgrade head` | 成功往返 |
| 外键存在性 | `select conname from pg_constraint where conrelid='rule_sets'::regclass and contype='f'` | `fk_rule_sets_active_version_id` |
| 全新库路径 | 空库 `alembic upgrade head` | 成功（0001 建表 + 0010 守卫跳过） |
| 探针包构建 | `python probe_packages/build_packages.py` | amd64 `sha256=9d513a85…`、arm64 `sha256=fdc829a7…`，manifest 含 `ruleset_client.py` |
| 阶段 2 用例 | `pytest` 四组 | 116 passed |

## 7. 已知限制与未验证项

- **未在本机生产库执行 0010**：真实升级在阶段 6 进行（需先备份）。本阶段在独立 scratch 库上验证了 0009→0010 与全新库两条路径。
- **未在真实 Kali 探针上执行热更新**：阶段 6 验证。本阶段以进程内客户端 + 真实规则包字节验证了全部拒绝/回退分支。
- **规则编辑 UI 只覆盖"查看发布记录 + 发布 + 回滚 + 探针同步状态"**：单条规则的编辑仍走既有 `/api/v1/dlp/rules` 与托管规则文件，尚未提供逐条在线编辑器。
- **`enabled=false` 的规则会进入发布包**（标记为禁用），由探针引擎跳过；这样规则集内容与运维预期一致，但包体因此略大。
- **规则包未做签名**：完整性依赖 SHA256 + 已认证通道，符合主提示词"SHA256 不替代认证或传输信任"的定位；未引入独立签名密钥体系。
- **并发发布的串行化**依赖数据库唯一约束（`UNIQUE(rule_set_id, version)`）与事务，未额外引入发布锁；同一版本并发发布时后者会因唯一约束冲突返回 400。
