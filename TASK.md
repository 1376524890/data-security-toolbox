# Current Task

> 本文件只记录**当前正在做的任务**。历史任务见文末 `## Task History`。
> 长期稳定信息见 `AGENTS.md`，项目整体状态见 `PROJECT_STATUS.md`。

## Goal

让工具在**全部使用真实数据**的前提下，把「数据安全合规检查服务」相关功能做到演示可用：
所有入口点开都有真实内容，业务逻辑正确，可直接向领导演示，并能回答技术细节提问。

## Requirements

1. 用户明确要求：**不做演示用假数据**，所有数据必须来自真实链路（探针采集、真实 PCAP、真实情报源、真实下发）。
2. 修复用户实际点到的四处前端缺陷：驾驶舱「敏感数据分布 / 严重等级分布」、PCAP 工作台告警证据、协议分布图，以及「资产有风险但 IOC / 风险关联为空」。
3. 交付演示方案：演示方法、着重点、可回答的技术细节、与 `SIMP-SRD-数据安全合规检测系统操作手册-敏感信息发现(1).docx` 的异同与优势、未来展望。
4. 建立仓库级上下文，使新会话只读仓库即可恢复状态：`AGENTS.md` / `TASK.md` / `PROJECT_STATUS.md` / `docs/architecture.md`。

## Completed

### 资产详情三个页签全部有真实内容（本轮，已部署验证）

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

### 其他已完成

- 前端可见缺陷 3 项已修复并验证（`e815a54`）：PCAP 告警证据取错对象、协议分布图被链路层协议淹没、驾驶舱环形图打印英文枚举且顺序随机。
- 演示方案文档 `docs/领导演示方案.md`（预检清单、五幕脚本、技术问答、SIMP-SRD 对比、路线图）。
- 版本 v2.10.0（平台 2.10.0 / 探针 3.5.0）：探针远程卸载闭环，E2E 验证目标机零残留。
- 建立四个上下文文件：`AGENTS.md`、`TASK.md`、`PROJECT_STATUS.md`、`docs/architecture.md` 增补。
- 核实库内无测试数据：`GET /api/v1/test/status` → `present=false`。
- 真实情报同步：Feodo Tracker 回源真实但**官方 recommended 列表只有 1 条**（`# END 1 entries`），
  落库 `50.16.16.211`（任务 #1753 Success）。这不是缺陷，因此 IOC 页签在未命中时为空属预期。

## In Progress

无。本轮代码改动已全部构建、部署、验证，等待用户对下面两个决策项拍板。

## TODO

- [ ] 决策项：资产详情 IOC 页签在「情报库无该主机命中」时如何呈现（保持为空 / 展示该主机流量中真实观测到的目标）。
- [ ] 决策项：控制台顶部「测试数据 → 导入/清除测试数据」下拉菜单（`frontend/src/App.vue`）是否在生产构建中隐藏。
- [ ] 可选增强：`protocol_engine` 的 `PROTO_DNS_TUNNEL_001` 证据只有域名与报文计数，不含主机地址，
      因此这类事件仍归属 `global`（当前 55 条事件中 1 条）。若要归属需在 DNS 解析层保留查询源地址。
- [ ] 更新 `docs/领导演示方案.md` 的数字与「已修复项」表述（本轮改动后需重新采集）。
- [ ] 可选：把本轮改动发成补丁版本 `v2.10.1`，使演示版本号与内容严格对应。

## Modified Files

本轮（未提交）：

| 文件 | 修改原因 |
| --- | --- |
| `backend/app/incident_engine/engine.py` | 新增 `_asset_identity()`（字典资产取地址作为身份，`_short_asset` 仍是展示标签）；`evidence_asset_keys()` / `evidence_ioc_keys()` 公共化；事件证据新增 `assets`；读 `src`/`dst`/`metrics` 主机 |
| `backend/app/incident_engine/attribution.py` | 新增：按事件自身已存 findings 重算归属（只改派生字段，不动 fingerprint） |
| `backend/app/api/v1.py` | `asset_detail` 关联检测与关联事件改为多拼写匹配 + 精确判定；IOC 联动读 `matched_iocs`；新增 `POST /incidents/rebuild-attribution`（带审计） |
| `backend/app/workers/tasks.py` | findings 去重签名复用统一身份解析 |
| `backend/tests/integrations/test_incident_engine.py` | 新增 4 个回归用例（嵌套资产、src/dst 与 metrics 拼写、多主机、归属重算） |
| `AGENTS.md` / `TASK.md` / `PROJECT_STATUS.md` / `docs/architecture.md` | 跨会话上下文 |

上一轮（`e815a54`）：`backend/app/api/v1.py`、`backend/app/services/protocol_service.py`、`backend/tests/test_protocol.py`、
`frontend/src/utils/mapping.ts`、`frontend/src/components/SeverityTag.vue`、`frontend/src/components/DonutChart.vue`、
`frontend/src/modules/dashboard/Dashboard.vue`、`frontend/src/modules/network/ProtocolAnalysis.vue`、
`frontend/src/modules/network/PcapWorkbench.vue`。

## Known Issues

1. `PROTO_DNS_TUNNEL_001` 证据不含主机地址 → 该事件仍为 `global`（1/55）。属真实「无主机」证据，非查询缺陷。
2. `iocs` 表只有 1 条真实指标（Feodo 官方 recommended 列表当前仅 1 条），因此资产 IOC 页签在未命中时为空。
   要充实需接入真实情报源：URLhaus（需服务端密钥）或自建 JSON/CSV（需 `CUSTOM_INTEL_URL`），或导入真实 MISP/STIX 文件。
3. `audit_logs` 覆盖面仍小：目前只有 `data_catalog.py` 的 rebuild/backfill 与本轮新增的 `incidents.rebuild_attribution`。
4. `vulnerabilities` 表无写入方（全仓仅 `asset_detail` 读取），CVE 命中以 Finding（`rule_id = CVE_*`）形式存在。
5. 资产 214 条里 200 条是 `192.168.191.168` 的 service 级资产（端口扫描真实产物），非脏数据。
6. 5 个历史遗留失败用例在完整仓库布局下依然失败（见 `Verification` 的基线说明）。

## Verification

### 已执行并记录结果

| 验证 | 命令 / 方式 | 结果 |
| --- | --- | --- |
| 语法检查 | `python -m py_compile` 四个改动文件 | SYNTAX OK |
| 空态复现 | `GET /api/v1/assets/{id}` | 修复前：findings=100 但 incidents=0、iocs=0 |
| 归属重算（首次） | `POST /api/v1/incidents/rebuild-attribution` | `scanned=54, recovered=50, relabelled=53, globals_before=16, globals_after=0, hosts=33` |
| 归属重算（幂等复跑） | 同上再跑一次 | `scanned=55, recovered=1, globals_before=2, globals_after=1`（仅剩 DNS 隧道那条真实无主机事件） |
| 资产页复核 | `GET /api/v1/assets/{2,4,5,14,209}` | 见 Completed 表格，三个页签均有真实内容 |
| 漏检定量 | `psql: select count(*) from detection_findings where evidence::text like '%192.168.191.130%'` | 98 条；修复后该资产关联检测返回 98/99 条，与库内一致 |
| 后端测试（对照） | 同一镜像 + 挂载源码，`python -m pytest -q`；HEAD(e815a54) 工作树 vs 当前工作树 | HEAD **521** 用例 / 16 失败；当前 **525** 用例 / **16 失败，失败集合完全一致 → 零回归** |
| 新增用例 | `pytest tests/integrations/test_incident_engine.py -q` | 8 passed（含 4 个新增） |
| 情报同步 | `POST /api/v1/intelligence/providers/feodo/sync` | 任务 #1753 Success；库内 1 条真实指标 |
| 部署 | 重建 `source-backend` 与 `source-worker/beat/deployment-worker` 镜像后重建容器 | backend/worker healthy，beat/deployment-worker Up |

### 重要说明：测试基线口径

镜像不包含 `tests/`、`pyproject.toml`、`probe_packages/`，因此在容器里直接 `pytest` 会因环境缺失产生 16 个失败
（`test_package.py` 4 个、`test_distribution.py` 10 个、`test_health`、`test_gap_fixes::test_integrations_...`），
与代码无关。本轮用「同一镜像 + 挂载 `app/tests/pyproject.toml/probe/shared/probe_packages` + `-w /app`」的固定口径，
对 HEAD 与当前工作树各跑一次，**失败集合逐条比对完全一致**，据此判定零回归。
运行方式（可复现）：

```powershell
$src = (Resolve-Path ".\00-数据安全工具箱\source").Path
docker run --rm -v "${src}\backend\app:/app/app" -v "${src}\backend\tests:/app/tests" `
  -v "${src}\backend\pyproject.toml:/app/pyproject.toml" -v "${src}\probe:/app/probe" `
  -v "${src}\shared:/app/shared" -v "${src}\probe_packages:/app/probe_packages" `
  -w /app source-backend:latest python -m pytest -q
```

## Next Step

1. 提交本轮改动（建议信息 `fix(incident,api): attribute findings and incidents to every asset they touch`）。
2. 收两个决策项（IOC 页签语义、测试数据菜单）后决定是否再改。
3. 重新采集演示数字并更新 `docs/领导演示方案.md`。
4. 可选：发 `v2.10.1` 补丁版本。

## Task History

| 日期 | 任务 | 结果 | Commit |
| --- | --- | --- | --- |
| 2026-09-17 | 探针远程卸载（含生产文件清理，E2E 零残留） | 完成并发布 | `735a657` / `3967e82` (v2.10.0) |
| 2026-09-17 | 下发/回收各阶段中文标签 + 演示方案文档 | 完成 | `2ff8390` |
| 2026-09-17 | 前端三处可见缺陷 + 资产详情关联查询 | 完成，46 端点全 200 | `e815a54` |
| 2026-09-17 | 建立 `AGENTS.md` / `TASK.md` / `PROJECT_STATUS.md` / `docs/architecture.md` | 完成 | （本次） |
| 2026-09-17 | 资产归属根因修复 + 事件归属重算端点 + 回归用例 | 完成并部署验证，零回归 | （本次） |
