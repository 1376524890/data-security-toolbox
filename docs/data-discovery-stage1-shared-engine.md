# 阶段 1 实施记录：共享检测引擎与报告安全边界

- 前置：`docs/data-discovery-3.3.1-baseline.md`（阶段 0）。
- 基线版本：平台 2.7.0 / 探针 3.3.1；本阶段**不递增版本号**（版本号在阶段 6 统一提升）。
- 本记录中所有数字均为本机实测，命令与结果见第 5 节；未验证项目集中在第 6 节，未做任何"看起来完成"的声明。

## 1. 阶段完成判定

阶段 1 的完成标准是：**文件扫描与 NetDLP 确实调用共享代码，旧输出与认证保持兼容，而不只是新增一个无人调用的类**。逐条对照：

| 阶段 1 要求 | 实测证据 |
|---|---|
| 抽取轻量共享引擎与上下文/结果/Evidence | `shared/sensitive_detection/`（11 模块，无 FastAPI/SQLAlchemy/Celery 依赖） |
| 适配本地规则、字段提示、平台规则、Presidio 来源信息 | `rules.py` 12 条内置规则；`entities.py` 别名/分级；`recognizers.py` 静态来源标注 |
| 探针与服务端 NetDLP 使用同一实现，保留旧输出适配器 | `probe/data_assets.py`、`app/services/dlp_service.py` 均经 `app/services/sensitive_engine.py` 取同一引擎；`app/engine/data_engine/engine.py` 复用同一规则表 |
| 报告安全序列化 + 服务端校验 + 不误拦 bootstrap/token | 探针 `guard_report()` + 服务端 `validate_report()` 返回 422；`test_probe_authentication_bodies_are_not_run_through_the_report_guard` 通过 |
| 打通 Docker build context、包构建、install.sh、依赖 | 第 4 节四条路径均已改并实测（含容器内真实安装） |
| 测试：DLP 回归、数据发现回归、多 Evidence 合并、validator、正则超时、Presidio 来源区分、嵌套原值拒绝、合法字段名不误拒、无 NLP 模型可启动 | `backend/tests/shared/`（63 用例）+ 既有回归用例全部通过 |

## 2. 已完成项

### 2.1 共享引擎 `shared/sensitive_detection/`

| 模块 | 作用 |
|---|---|
| `context.py` | `SensitiveDetectionContext`，与平台流水线 `engine.core.context.DetectionContext` **并存**，不替换 |
| `result.py` | `DetectionHit` / `Evidence`：**结构上不存在存放匹配值的字段**，"报告不含原值"由数据结构保证 |
| `entities.py` | 规范实体名、别名表（`CN_PHONE`/`PHONE_NUMBER` → `PHONE`）、结构型元数据集合、L1–L4 与 Critical/High/Medium/Low 映射、`legacy_name()` 兼容旧小写类别名 |
| `validators.py` | 白名单校验器：身份证（长度/生日/校验位）、银行卡（Luhn）、邮箱（形状硬校验）、手机号；不允许 eval/exec/远程代码 |
| `confidence.py` | 版本化置信度（`CONFIDENCE_VERSION=1.0.0`）；同一 span 的重复证据取最大值而非累加；字段名证据上限 0.5 |
| `matching.py` | 正则匹配的时间/长度/数量上限；`regex` 优先（可超时），缺失时降级 `re` 并如实上报能力 |
| `rules.py` | 12 条内置规则（JSON 可序列化），含仅字段/上下文类（姓名、地址、医疗记录、用户标识） |
| `engine.py` | `SensitiveDetectionEngine`，Regex/Keyword/FieldName/Validator 证据合并、span 去重、能力自述 |
| `ruleset.py` | 规则包加载/校验/SHA256/版本兼容（阶段 2 复用） |
| `report_guard.py` | 结构白名单 + 禁止键 + 敏感串脱敏；`validate_report` / `sanitize_report` |

实测能力自述（`build_engine().capabilities()`）：`engine_version=1.0.0`、`regex_backend=regex`、`regex_timeout=True`、`rule_count=12`、实体集含 PHONE/ID_CARD/BANK_CARD/EMAIL/API_KEY/TOKEN/CREDENTIAL/NAME/ADDRESS/USER_ID/MEDICAL_RECORD。

### 2.2 调用点改写（三条调用链统一）

- **探针文件扫描**：`probe/data_assets.py` 通过 `<app_root>/shared` 导入共享引擎；类别仍以旧小写名上报（`phone`/`id_card`/…），并新增 `engine_version` 与每文件 `evidence.hits`；上下文类命中低于 `CATEGORY_MIN_CONFIDENCE=0.5` **不**把整文件标为敏感。
- **服务端文件引擎**：`backend/app/engine/data_engine/engine.py` 的 `REGEX_RULES` 改为由共享规则包生成，`scan_text()` 保留旧返回键（`high_entropy_secrets: []`），新增 `sensitivity_level`/`severity`；`presidio_status()` 不再吞掉错误。
- **网络 DLP**：`app/services/dlp_service.py::inspect_content` 走共享引擎，`samples` 恒为空数组（保留旧 shape）；`app/api/libraries.py::list_dlp_rules` 的 builtin 从共享包读取，旧 rule id（`phone`/`id_card`/`bank_card`/`email`/`api_key`/`token`）保持不变。
- **Presidio 来源区分**：静态提取标 `rule_source=presidio_static`，真正运行 recognizer 才标 `presidio_runtime`；`fallback_scan()` 不再返回匹配文本。

### 2.3 报告安全边界（本阶段新增的硬约束）

- 探针侧：`probe/data_assets.py::guard_report()` 在 `report_id`/`task_id` 落盘**之前**清洗整份报告（丢弃禁止键、脱敏形如原值的字符串），并把清洗计数写入 `report_guard` 字段随报告上报 —— 真实脱敏可见，不静默吞掉。
- 服务端：`backend/app/api/extensions.py::data_asset_inventory` 在鉴权之后、入库之前独立校验同一份结构；违规返回 **422** 且只回传 `{path, code}`，**不回显违规值**。
- 作用域：仅数据资产报告。探针 bootstrap/token 认证与后续心跳请求体不经过该校验，避免"合法 token/password 字段被误拦"。

### 2.4 测试隔离修复

`backend/tests/conftest.py` 在导入任何应用模块前固定 `APP_ENV=development`、`PROBE_BOOTSTRAP_TOKEN=""`、`DATABASE_URL=sqlite:///./data/test.db`、存储/报告/集成目录指向临时目录、`ADMIN_PASSWORD=test-admin-password`。修复前 20 failed（读取了生产 `.env`），修复后仅剩环境性失败。**未**固定 `PRESIDIO_ENABLED=false`：固定它会破坏 `test_adapter_pipeline`。

## 3. 文件变化

### 3.1 新增

- `shared/__init__.py`、`shared/sensitive_detection/`（`__init__`/`context`/`entities`/`validators`/`confidence`/`matching`/`result`/`rules`/`engine`/`ruleset`/`report_guard`）
- `backend/app/services/sensitive_engine.py`（平台适配层，只做路径引导与旧 shape 转换，不含检测逻辑）
- `backend/app/services/report_guard.py`（服务端校验入口，复用共享实现）
- `backend/tests/shared/`（`conftest.py`、`test_sensitive_detection.py`、`test_report_guard.py`、`test_engine_wiring.py`、`test_distribution.py`）
- `.dockerignore`（根 context 的构建忽略表）

### 3.2 修改

| 文件 | 变化 |
|---|---|
| `backend/app/services/dlp_service.py` | `inspect_content` 改走共享引擎 |
| `backend/app/engine/data_engine/engine.py` | 规则表来自共享包；证据不再含样本 |
| `backend/app/api/libraries.py` | builtin 规则来自共享包，旧 id 保持 |
| `backend/app/integrations/presidio/recognizers.py` | 去除第二份正则表；静态/运行时来源标注；`presidio_status()` |
| `backend/app/integrations/presidio/adapter.py` | 证据改为 `entity_type/count/rule_source/rule_sources/engine`，无 `samples` |
| `backend/app/api/extensions.py` | `DataAssetReport.report_guard` 字段 + 服务端 422 校验 |
| `probe/data_assets.py` | 改用共享引擎；新增 `guard_report()` |
| `probe/probe.py` | 数据资产报告落盘前调用 `guard_report()` |
| `probe/install.sh` | 安装 `shared/`；新增可写规则目录 `RULES_DIR` 并纳入 `ReadWritePaths`；缺共享包时**安装即失败** |
| `probe/requirements.txt` | 新增 `regex==2026.9.10`、`openpyxl==3.1.5` |
| `probe_packages/build_packages.py` | 打包 `shared/` 全树并写入 manifest `files` |
| `docker-compose.yml` | 4 个后端镜像改为 `context: .` + `dockerfile: backend/Dockerfile` |
| `backend/Dockerfile` | COPY 路径改为根 context 相对路径；新增 `COPY shared ./shared` |
| `backend/tests/conftest.py` | 测试隔离固定 |
| `backend/tests/test_dlp_detection_quality.py` | 断言"报告不含原值"不变量 |
| `docs/data-discovery-3.3.1-baseline.md` | 更正 3 处事实（见 6.7） |
| `backend/.dockerignore` | **删除**：context 已移至仓库根，根 `.dockerignore` 取代 |

### 3.3 保持不动

阶段 0 记录的既有未提交改动一律未 reset/覆盖：`.env.example`、`backend/app/core/config.py`、`docs/dlp-detection-quality.md`、`frontend/package.json`、`frontend/package-lock.json`，以及同一批中本阶段有叠加修改的 `dlp_service.py`、`extensions.py`、`docker-compose.yml`、`test_dlp_detection_quality.py`（NetDLP 误报修复部分保持原样）。

## 4. 四条分发路径（阶段 0 的 R2/R3 风险）

| 路径 | 结论 | 实测方式 |
|---|---|---|
| 探针包 | `build_packages.py` 复制 `shared/` 全树；manifest `files` 为**显式文件路径**，因此既有 `package.py::find_package()` 的逐文件存在性校验**无需改语义**即可覆盖共享模块 | 实跑构建，检查 tar 与 manifest；`test_distribution.py` |
| 远端安装 | `install.sh` 安装到 `${APP_DIR}/shared/`；缺共享包直接 `exit 1` | 在 `python:3.11-slim` 容器内真实执行安装脚本（桩 `systemctl`），确认 `/tmp/app/{probe,shared}` 布局、`ReadWritePaths` 含规则目录、`rules` 目录 `700 dstprobe`，并从安装目录成功导入并识别出 `['id_card', 'phone']` |
| Docker build context | 4 个后端服务改为根 context；`Dockerfile` 增 `COPY shared ./shared` | `docker compose config --quiet` 通过；`test_distribution.py` 断言无 `context: ./backend` 残留 |
| 依赖 | 探针 requirements 锁定 `regex`（真实超时）与 `openpyxl`（阶段 3） | 容器内 `pip download` 确认两个版本可解析（含 cp311 manylinux wheel） |

`install.sh` 语法另经 `bash -n` 校验通过（`bash` 在 Windows 主机不可用，故在容器内执行）。

## 5. 验证证据

| 命令 | 结果 |
|---|---|
| `pytest backend/tests/shared -q` | **63 passed** |
| `pytest backend/tests -q --tb=no`（全量） | 收集 **289**，**283 passed / 5 failed / 1 skipped** |
| `python probe_packages/build_packages.py` | amd64 `sha256=67b0661d…`、arm64 `sha256=6f3eb37e…`（每次构建重新生成，manifest 同步记录） |
| `docker compose config --quiet` | 通过 |
| `ruff check --select F401,F601,F811,F841,B905 shared probe backend/app/...` | 仅剩 1 项**既有**问题 `probe/probe.py:705`（见 6.6） |

失败的 5 项全部为环境性，已逐条核实与本次改动无关（阶段 0 记录的同类清单）：

| 用例 | 原因 |
|---|---|
| `engine/test_protocol_engine.py::test_protocol_engine_runs_on_fixture` | 主机无 `tshark`（`protocol_service.py:61`），本阶段未触碰该模块 |
| `test_protocol_service.py::test_stream_tshark_watchdog_timeout` | 同上 |
| `test_protocol_service.py::test_parse_pcap_total_exceeds_index_limit` | 同上 |
| `probe/test_probe_identity.py::test_first_registration_persists_identity` | Windows `chmod` 语义（实测 `438`，断言 `0o600`） |
| `test_api.py::test_health` | 本机无 Redis，健康状态返回 `degraded` |

## 6. 真实限制与未完成事项

1. **无 NER**：姓名、地址、医疗记录、用户标识只有字段名/上下文证据，置信度上限 0.5，`field_only=True` 如实上报；不得当成已完成识别。
2. **无超时后端时的兜底缺口（阶段 2 必须处理）**：`regex` 缺失时引擎降级 `re`，`capabilities()['regex_timeout']=False`。此时**恶意规则包可导致匹配长时间占用**。阶段 2 的规则包热加载必须在这种后端下拒绝加载外部规则包并保留内置包，并上报原因。
3. **Presidio 运行时路径未实测**：本机无 NLP 模型，实测只覆盖 `presidio_static` 与 `presidio_status()` 的原因上报；`presidio_runtime` 分支未被真实执行（测试按状态二分断言，不伪造运行时成功）。
4. **解析能力未实现**：XLSX/SQL.GZ/CSV 采样解析属阶段 3；本阶段仅锁定 `openpyxl` 依赖，未新增 parser。探针现有 `.xlsx` 处理仍是"按扩展名登记"。
5. **arm64 未实机验证**：arm64 包已构建，但仅在 amd64 主机与容器内验证。
6. **既有缺陷（未修改，交由阶段 2）**：`probe/probe.py:705` heartbeat `metadata` 字典键 `"agent_version"` 重复（`F601`），后一处静默覆盖前一处；阶段 2 增加 `current_ruleset_version`/`capabilities` 时应一并修正。
7. **基线文档更正**：①用例总数 266 → **226**（阶段 1 后 289）；②`conftest.py` 的 `PRESIDIO_ENABLED=false` 已删除；③`test_adapter_engine_runs_in_pipeline` 的失败原因由"tshark"更正为"上述被删除的环境变量"，该用例现已通过。
8. **`make lint` 在本仓库不可用**：镜像与 venv 均未安装 `ruff`；本次为校验新代码临时在 venv 安装 `ruff 0.16.7`（仅开发工具，未写入 requirements）。
9. **未在 Linux 探针实机验证**：安装脚本仅在容器内以桩 `systemctl` 验证文件布局与导入，systemd 真实行为留待阶段 6 在 Kali 探针上验证。

## 7. 下一阶段输入（阶段 2：中央 RuleSet 与热更新）

- `shared/sensitive_detection/ruleset.py` 已提供 `load_rule_pack()`（SHA256 校验、schema/engine 版本兼容、`min_agent_version`）与 `build_local_pack()`（随包基线快照），阶段 2 可直接复用。
- Alembic 迁移起点为 `0009_probe_data_assets`（线性 0001→0009），新增迁移应基于 0009。
- `probe/install.sh` 已准备 `/var/lib/data-security-toolbox/rules`（`700 dstprobe`，已纳入 systemd `ReadWritePaths`）用于 `current/previous/staging`。
- 探针心跳需新增 `current_ruleset_version`/`capabilities`，并修正 6.6 的重复键缺陷。
- 平台既有规则入口 `/api/v1/dlp/rules`（`libraries.py`）需成为新规则服务的兼容入口，不产生第二套不一致规则库。
- 需要在阶段 2 落实的硬约束：无超时后端时拒绝加载外部规则包（见 6.2）。
