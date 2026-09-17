# Current Task

> 本文件只记录**当前正在做的任务**。历史任务见文末 `## Task History`。
> 长期稳定信息见 `AGENTS.md`，项目整体状态见 `PROJECT_STATUS.md`。

## Goal

让工具在**全部使用真实数据**的前提下，把「数据安全合规检查服务」相关功能做到演示可用：
所有入口点开都有真实内容，业务逻辑正确，可直接向领导演示，并能回答技术细节提问。

本轮聚焦：**安全引擎的规则匹配与「规则」显示为空**。

## Requirements

1. 用户提问：「安全引擎的规则是不是都正确匹配到了规则，为什么规则的显示都是空？」
2. 用户明确要求：**不做演示用假数据**，所有数据必须来自真实链路；修复只能是「纠正真实数据的错误归属」，不能新增/伪造记录。
3. 保持既有接口路径 / 返回结构兼容（只做**追加**字段与**新增**查询参数）。

## Completed

### 根因一：规则解释器把引擎名写死成 `rules`（幽灵引擎）

`backend/app/rules/interpreter.py::interpret_rules()` 硬编码 `engine="rules"`，而 `TrafficEngine`（网络规则）与
`ComplianceEngine`（合规规则）都调用它。注册表里**根本不存在** `rules` 这个引擎，因此：

- 78 条网络规则检测（`NET_SCAN_001`）挂在幽灵引擎下；安全引擎页面按引擎过滤全部返回 0；
- 检测中心「引擎」列显示一个不存在的值；66 条告警 `source='rules'`。

修复：`interpret_rules(context, rule_dir, engine)` 由调用方传入 `self.name`。

**真实数据归属纠正**（不新增、不删除任何 finding，仅改engine字段）：

| 表 | 变更 | 说明 |
| --- | --- | --- |
| `detection_findings` | 79 行 `rules` → `traffic_engine` | 78 行历史 + 1 行（13:50 旧镜像产生的最后一条） |
| `incidents.findings.items[*].engine` | 18 条事件内同一批条目 | `fingerprint` 不含 engine，故身份不受影响 |
| `alerts.source` | 66 行 `rules` → `traffic_engine` | fingerprint 未改，见 `Known Issues` #1 |

正向验证：用**真实 PCAP（pcap 1807）**重新发起分析（任务 **#1852** Success）→ 新 finding `id=820`
`engine=traffic_engine, rule_id=NET_SCAN_001`，即新代码不再产生 `rules`。

### 根因二：前端引擎下拉是硬编码，和落库值完全对不上

三处硬编码列表与 `detection_findings.engine` 的真实取值不一致，导致**所有**过滤都为空：

- `EngineDetail.vue`：`['zeek','suricata','sigma','wazuh','osquery','openscap']`
- `DetectionCenter.vue`：`['traffic','protocol','zeek','suricata','data','sigma','ioc','compliance']`
- `SensitiveDiscovery.vue`：`engine: 'data'`（真实值是 `data_engine`）

修复：`GET /engine/registry` 追加 `slug`（控制台路由段）/ `label`（中文名）/ `rule_count` /
`detection_engine`（真正落库的引擎名）/ `detection_count`（已产生检测数），前端全部改读注册表；
`SensitiveDiscovery.vue` 改 `data_engine`。

### 根因三：规则数被 `/health` 覆盖成空

`EngineDetail.vue` 原实现 `{ ...item, rule_count: health[name]?.rule_count }`，而 `/health` 只有
`tshark/zeek/suricata` 三个键 → `Sigma/Wazuh/osquery/OpenSCAP` 的「规则数」渲染成 `-`（空）。
同时 Sigma 页的「Sigma 规则资源」读 `/offline/resources` 里 `resource_type='sigma_rules'`，
而库里只有 `grype_db` → 恒显示「暂无 Sigma 规则资源」。

修复：规则数与规则清单统一由**注册表 + `GET /rules?engine=`** 提供；
「规则卡片的规则数 == 规则清单条数」这一不变量已由测试锁定。

### 附带修复

- `GET /rules` 现在返回 `engine` 字段（`logs`→`sigma_log_engine`、`network`→`traffic_engine`、
  `compliance`→`compliance_engine`、`data`→`data_engine`、suricata 规则→`suricata`），并支持 `engine=` 过滤。
- 注册表 `rule_count` 与 `/rules` 共用同一规则库统计口径 → 数字永远与清单一致。
- `workers/tasks.py::_worker_capability()` 的 suricata `rule_count` 原来只统计离线目录 → 恒为 0（假 0）；
  现按 `run_suricata` 真正加载的规则文件统计（实测 2 条 `sid:`）。
- `frontend/src/router/menu.ts` 安全引擎组新增 6 个**平台引擎**入口
  （协议/流量/数据/防泄露/合规/威胁情报），使真正产生检测结果的引擎可达。

### 部署后实测（真实数据）

| 菜单/入口 | 解析到的引擎 | 卡片规则数 | 规则清单条数 | 检测数 |
| --- | --- | --- | --- | --- |
| zeek | `zeek` | 0 | 0 | 0 |
| suricata | `suricata` | 1 | 1 | 0 |
| sigma | `sigma_log_engine` | 6 | 6 | 0 |
| wazuh / osquery / openscap | 同名 | 0 | 0 | 0 |
| 协议检测引擎 | `protocol_engine` | 0 | 0 | **375** |
| 流量检测引擎 | `traffic_engine` | 3 | 3 | **98** |
| 数据检测引擎 | `data_engine` | 1 | 1 | 0 |
| 防泄露检测引擎 | `dlp_engine` | 0 | 0 | **14** |
| 合规检测引擎 | `compliance_engine` | 1 | 1 | **1** |
| 威胁情报引擎 | `threat_intel` | 0 | 0 | **332** |

`/dashboard/engines` 合计 820 条（与 `detection_findings` 总数一致），库内 `engine='rules'` 已归零。

## In Progress

无。代码、真实数据归属、镜像、容器均已更新并验证。

## TODO

- [ ] 决策项：资产详情 IOC 页签在「情报库无该主机命中」时如何呈现（保持为空 / 展示该主机流量中真实观测到的目标）。
- [ ] 决策项：控制台顶部「测试数据 → 导入/清除测试数据」下拉菜单（`frontend/src/App.vue`）是否在生产构建中隐藏。
- [ ] 66 条历史告警的 `fingerprint`/`correlation_key` 仍是 `rules` 派生值（本轮只纠正了可见的 `source`）。
- [ ] 更新 `docs/领导演示方案.md` 的数字与「已修复项」表述（本轮改动后需重新采集）。
- [ ] 可选增强：`protocol_engine` 的 `PROTO_DNS_TUNNEL_001` 证据只有域名与报文计数，不含主机地址，
      因此这类事件仍归属 `global`（当前 56 条事件中 1 条）。
- [ ] 「威胁情报 → 检测规则」（`RulesCenter.vue`）的页签仍按 `type`（`sigma`/`suricata`/`yara`）分组，
      因此 `app/rules/network/*.yaml`、`app/rules/compliance/*.yaml` 会显示在 **Sigma 页签**下。
      本次已让接口给出真实的 `engine` 标签（数据已正确），但页签尚未改为按引擎分组 —— 页面不为空，
      属「标签不够精确」，未在本次修改范围内。
- [ ] 可选：把本轮改动发成补丁版本 `v2.10.1`，使演示版本号与内容严格对应。

## Modified Files

本轮（已提交）：

| 文件 | 修改原因 |
| --- | --- |
| `backend/app/rules/interpreter.py` | `interpret_rules()` 引擎名改为调用方传入，修掉幽灵引擎 `rules` |
| `backend/app/engine/traffic_engine/engine.py` | 传入 `self.name` |
| `backend/app/engine/compliance_engine/engine.py` | 传入 `self.name` |
| `backend/app/api/v1.py` | 新增 `ENGINE_PRESENTATION`；`/engine/registry` 追加 slug/label/rule_count/detection_engine/detection_count；新增 `_rule_file_entries()` 作为规则库唯一来源；`/rules` 增加 `engine` 标签与 `engine=` 过滤 |
| `backend/app/workers/tasks.py` | suricata 规则数按实际加载的规则文件统计（原为恒 0） |
| `backend/tests/engine/test_traffic_engine.py` | 新增 2 个回归用例（引擎归属） |
| `backend/tests/test_api.py` | 新增 3 个回归用例（注册表契约、规则库标签与计数一致、`/rules` 引擎过滤） |
| `frontend/src/api/engine.ts` | `EngineInfo` 追加 slug/label/rule_count/detection_engine/detection_count |
| `frontend/src/api/rules.ts` | `RuleItem.engine`；`listRules(query)` 支持 `engine`，并修正原本无效的 `type` 参数名为 `rule_type` |
| `frontend/src/types/integration.ts` | 补 `rule_count`/`rule_source`（接口本来就返回） |
| `frontend/src/modules/engines/EngineDetail.vue` | 下拉/规则数/规则清单/检测列表全部改读注册表；新增规则清单表（可展开看规则正文） |
| `frontend/src/modules/operations/detections/DetectionCenter.vue` | 引擎过滤项改由注册表生成 |
| `frontend/src/modules/data-security/SensitiveDiscovery.vue` | `engine: 'data'` → `'data_engine'` |
| `frontend/src/router/menu.ts` | 安全引擎组新增 6 个平台引擎入口 |
| `TASK.md` / `PROJECT_STATUS.md` / `docs/architecture.md` | 同步本轮结论 |

## Known Issues

1. **66 条历史告警的 fingerprint 未改**：`alerts.fingerprint = sha256(rule_id|source|asset|ioc)`，把 66 条历史实例重算成
   `traffic_engine` 派生值会与 13:59 新产生的正确告警（`a64dc8ad…`）**碰撞**，合并 66 条历史实例超出「标签纠正」的范围。
   影响：同一条件再次命中时会新建告警实例，而不是抑制递增旧的 66 条。**新数据的 fingerprint 是正确的。**
2. **两个「规则数」口径不同但都真实**：注册表 `rule_count` = 规则文件数（与规则清单一致，suricata=1）；
   `/health.suricata.rule_count` = 实际加载的 `sid:` 数（suricata=2）。
3. `zeek/wazuh/osquery/openscap` 规则数与检测数为 0 属**真实为空**：zeek 适配器加载的是脚本（`loaded_scripts`）而非规则文件；
   wazuh/osquery/openscap 未安装。不是显示缺陷。
4. `PROTO_DNS_TUNNEL_001` 证据不含主机地址 → 该事件仍为 `global`（1/56）。属真实「无主机」证据。
5. `iocs` 表只有 1 条真实指标（Feodo 官方 recommended 列表当前仅 1 条），资产 IOC 页签未命中时为空属预期。
6. `audit_logs` 覆盖面仍小（只有 `data_catalog` 的 rebuild/backfill 与 `incidents.rebuild_attribution`）。
7. `vulnerabilities` 表无写入方，CVE 命中以 Finding（`rule_id = CVE_*`）形式存在。
8. 完整仓库布局下仍有 16 个环境相关失败用例（见 `Verification` 的基线说明），与本轮改动无关。

## Verification

### 本轮已执行并记录结果

| 验证 | 命令 / 方式 | 结果 |
| --- | --- | --- |
| 语法检查 | 容器内 `python -m compileall`（`app`、`workers/tasks.py`） | 通过（exit 0） |
| 后端测试（本轮） | 固定镜像+挂载源码口径 `pytest -q` | **531 收集 / 16 失败，失败集合与 HEAD 基线逐条一致 → 零回归** |
| 新增后端用例 | `pytest tests/engine/test_traffic_engine.py tests/test_api.py -q` | 8 passed（仅 `test_health` 因无 Redis 失败，属既有基线） |
| 前端类型检查 | `npx vue-tsc --noEmit` | 通过（exit 0） |
| 前端单测 | `npx vitest run` | 8 文件 / **31 passed** |
| 修复前复现 | `GET /api/v1/detections?engine=<zeek…openscap>` | 六个适配器 **全部 total=0**；`engine=rules` = 78 |
| 修复后对照 | 同上（部署后） | 六个适配器仍为 0（真实），`protocol_engine=375`、`threat_intel=332`、`traffic_engine=98`、`dlp_engine=14`、`compliance_engine=1`，`rules` 归零 |
| 端到端正向验证 | `POST /api/v1/pcaps/1807/analyze`（真实 PCAP） | 任务 #1852 Success → finding 820 `engine=traffic_engine`（新代码不再写 `rules`） |
| 注册表契约 | `GET /api/v1/engine/registry` | 15 个引擎，`rule_count` 与 `/rules?engine=` 条数逐条相等 |
| Suricata 假 0 修复 | `GET /api/v1/health` | `suricata.rule_count` 0 → **2**（`dst_sensitive.rules` 的 2 个 sid） |
| 控制台可用性 | `GET http://localhost:8088/`、`/engines/traffic` | HTTP 200；构建产物内含新代码（`规则清单` / `Sigma 日志引擎` / `协议检测引擎`） |
| 数据一致性 | `psql: select engine, count(*) from detection_findings group by 1` | 无 `rules` 行；`incidents`/`alerts` 中 `"rules"` 归零 |

### 未执行

- 浏览器端截图确认：本机 cua 浏览器不可用（`Browsers: unsupported Codex auth method: apikey`），
  因此改为「接口契约 + 构建产物包含新代码 + 类型检查 + 单测」三重间接验证，未做像素级确认。

### 重要说明：测试基线口径

镜像不包含 `tests/`、`pyproject.toml`、`probe_packages/`，因此在容器里直接 `pytest` 会因环境缺失产生 16 个失败
（`test_package.py` 4 个、`test_distribution.py` 10 个、`test_health`、`test_gap_fixes::test_integrations_...`），
与代码无关。固定口径（可复现）：

```powershell
$src = (Resolve-Path ".\00-数据安全工具箱\source").Path
docker run --rm -v "${src}\backend\app:/app/app" -v "${src}\backend\tests:/app/tests" `
  -v "${src}\backend\pyproject.toml:/app/pyproject.toml" -v "${src}\probe:/app/probe" `
  -v "${src}\shared:/app/shared" -v "${src}\probe_packages:/app/probe_packages" `
  -w /app source-backend:latest python -m pytest -q
```

## Next Step

1. 提交本轮改动（建议 `fix(engine,api,ui): attribute rule findings to the engine that ran them`）。
2. 收两个决策项（IOC 页签语义、测试数据菜单）后决定是否再改。
3. 重新采集演示数字并更新 `docs/领导演示方案.md`。
4. 可选：发 `v2.10.1` 补丁版本。

## Task History

| 日期 | 任务 | 结果 | Commit |
| --- | --- | --- | --- |
| 2026-09-17 | 安全引擎规则归属修复（幽灵引擎 `rules`）+ 引擎下拉/规则显示改读注册表 + 真实数据归属纠正 | 完成并部署验证，零回归 | `573d9e9` |
| 2026-09-17 | 资产归属根因修复 + 事件归属重算端点 + 回归用例 | 完成并部署验证，零回归 | `0cf03de` / `8d0c3c8` |
| 2026-09-17 | 探针远程卸载（含生产文件清理，E2E 零残留） | 完成并发布 | `735a657` / `3967e82` (v2.10.0) |
| 2026-09-17 | 下发/回收各阶段中文标签 + 演示方案文档 | 完成 | `2ff8390` |
| 2026-09-17 | 前端三处可见缺陷 + 资产详情关联查询 | 完成，46 端点全 200 | `e815a54` |
| 2026-09-17 | 建立 `AGENTS.md` / `TASK.md` / `PROJECT_STATUS.md` / `docs/architecture.md` | 完成 | （`e815a54` 之后） |

### 上一轮详情（资产归属修复，`0cf03de` / `8d0c3c8`）

根因是「资产身份」被以三种互相矛盾的方式解读，修复后实测：

| 资产 | IP | 关联检测 | 关联事件 | 数据资产 |
| --- | --- | --- | --- | --- |
| 2 / 14 | 192.168.191.130（探针主机） | 0 → **99** | 0 → **20** | 100 |
| 4 / 5 | 192.168.110.168 | 52 | 0 → **6** | 0 |
| 209 | 192.168.191.168 | 100 | 0 → **28** | 0 |

1. **事件归属**：`incident_engine` 读不到真实字段——情报引擎把资产嵌在 `evidence.asset` 字典里（旧代码拼成
   `192.168.191.168:192.168.191.168:telnet:23`，任何资产页都匹配不上，还把一台主机按端口拆成多个事件）；
   流量引擎用 `src`/`dst`；规则引擎只在 `metrics["src:<ip>:ports"]` 里带主机。旧代码全部忽略 → 16 条事件退化成 `global`。
2. **多主机事件**：改为记录 `evidence.assets`（事件覆盖的全部主机），展示标签 `evidence.asset` 保留，资产页按成员归属判定。
3. **关联检测**：`asset_detail` 原先只匹配 `evidence.asset.ip` / `evidence.ip`，漏掉只出现在 `src`/`dst`/`metrics` 里的主机
   （实测 192.168.191.130 有 98 条真实 findings 被漏掉：rules 74 + dlp 14 + traffic 10）。
4. **IOC 联动**：补读威胁情报引擎的 `matched_iocs`。
5. **findings 去重签名**：`workers/tasks.py::_finding_signature()` 旧实现只看 `src_ip/dst_ip/asset`，对流量引擎 findings 恒为空串，
   会把不同主机的 findings 误合并；现复用同一套身份解析。

归属重算实测：`POST /api/v1/incidents/rebuild-attribution` 首次
`scanned=54, recovered=50, relabelled=53, globals_before=16, globals_after=0, hosts=33`；
再跑一次（幂等）`scanned=55, recovered=1, globals_before=2, globals_after=1`。

同期完成：前端可见缺陷 3 项（`e815a54`）、`docs/领导演示方案.md`、v2.10.0 探针远程卸载闭环、
四个上下文文件、核实库内无测试数据（`GET /api/v1/test/status` → `present=false`）。
