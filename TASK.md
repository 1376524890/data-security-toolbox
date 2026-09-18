# Current Task

> 本文件只记录**当前正在做的任务**。历史任务见文末 `## Task History`。
> 长期稳定信息见 `AGENTS.md`，项目整体状态见 `PROJECT_STATUS.md`。

## v2.11.0 发布（2026-09-18）

目标：把工作区里未提交的「引擎规则库 + PCAP 工作台」改动整理成 v2.11.0 发布。

- 版本：平台 2.10.0 → **2.11.0**（`backend/app/main.py`、`frontend/package.json`、`frontend/package-lock.json`）；
  探针未改代码，保持 **3.5.0**；迁移仍为 `0014_probe_removal (head)`，无需执行迁移。
- 文档：`CHANGELOG.md` 新增 `v2.11.0` 段（规则库、上游同步、命中快照、引擎总览、归属修复、PCAP 工作台、
  集成修复、验证结论）；`docs/versioning.md` 追加 `v2.11` 版本行；`PROJECT_STATUS.md` 更新版本表与发布状态。
- 标签：`v2.11.0`（注释标签，打在发布提交上）。
- 验证：前端 `npx vitest run` 34 passed、`npx vue-tsc --noEmit` 通过；后端在 `source-backend-1` 容器内
  （镜像自带 tshark）跑规则执行/告警/PCAP 工作台定向回归通过；全量后端 16 项失败与既有环境基线逐条一致。
  本机 Windows 直跑 `tests/test_pcap_workbench.py::test_native_exporter_retains_response_without_python_reassembly`
  会因缺 tshark 失败，属环境差异，容器内通过。
- 未做：未推送远端、未重建镜像（运行容器仍是发布前构建的镜像）、未操作真实探针主机、未导入测试数据。

## PCAP 工作台修复结果（2026-09-18 09:10，优先于下方快照）

用户目标：修复手动上传、展示从数据流分离的文件及文本/Hex、修复打开后的包列表。
本轮代码已部署到本机 backend / worker / beat / deployment-worker / frontend。

- 上传根因实测：现有 `2.pcapng` 上传返回 HTTP 200、`duplicate=true`、`id=651`，
  原页面忽略返回 ID，仅刷新按新旧排序的当前页，造成“上传没有成功”的观感。
  先前认定 120 秒超时就是本次根因缺少证据，现以该实际响应为准。
- 上传后直接定位返回的抓包，重复文件有明确提示；新任务自动跟踪进度并刷新结果。
  保留独立 30 分钟上传超时与进度，网关关闭请求缓冲；无效抓包返回明确错误。
  重复确认先于队列背压检查，队列繁忙不再阻止确认已存在的文件。
- 包列表改为上方全宽表、下方协议树/字节视图，提供分页和搜索；概览显示真实总数，
  标明已索引数。补齐 IPv6/非 IP 帧地址，时间保留微秒；Hex 列固定字符宽度防止错位。
- 新增 `services/pcap_files.py`，HTTP 上传文件/响应体及 TShark 原生对象导出独立于 DLP
  告警保存；标明缺包、限制与加密流。文件清单支持原始附件下载、分页文本/Hex/ASCII。
  文件预览是字节解码，不承诺 PDF/Office 等格式的文档正文渲染。
- 新 API `GET /pcaps/{id}/files/{sha256}`；原下载端点接受字符串文件 ID，并以本抓包的
  提取清单校验归属，不再信任事件中的任意存储路径。无需数据库迁移。
- 验证：后端相关 49 passed；前端 34 passed（含重复上传定位、翻页、文本/Hex 组件交互），
  typecheck、生产构建、nginx 配置及 diff 检查通过。无可用浏览器会话，未完成截图验收。
- 真实运行验证：原始 PCAP #2026 经手动上传接口产生 #2112 / 任务 #2144，分析 Success，
  38 个包，提取 5 项内容（含 16,227 字节的实际传输文件）；所有下载 SHA256 与 Hex 预览一致。
  同一文件再上传返回 #2112 与 duplicate=true。
- `2.pcapng` #651 重分析任务 #2145 为 Success；284 包，分页第二页返回 100 条，从第 101 包开始，
  第 101 包原始 518 字节、5 个协议层。该抓包未提取到文件，覆盖信息为 16 条加密流、4 个异常报文。
- 后端和 worker 健康；`/test/status` 为 present=false。未导入测试数据、未操作真实探针主机、未提交。

后续：旧抓包需重新分析才生成文件提取清单；本轮已重分析上述真实样本。全量后端既有 16 项失败
仍按下方规则库任务记录处理，本轮只运行与变更相关的回归。

## 规则库结果（2026-09-18，优先于下方历史快照）

本轮目标：修复安全引擎规则为 0，展示实际规则和告警命中依据，在线更新支持的上游规则，
并让本地引擎真正加载执行。代码、镜像与本机服务已更新，未操作真实探针主机。

- 已部署 backend / worker / beat / deployment-worker / frontend；入口 `http://localhost:8088/engines`。
- 通过前端网关实测全部 15 个引擎规则数非 0，清单共 3,512 项，逐引擎计数与清单一致。
  资源数包含规则文件、代码检查和敏感检测定义；不等于单条签名数。
- 已在线获取：Sigma 2,943 份兼容规则（635 份不支持已跳过）、Suricata ET Open 52 份文件、
  Zeek 234 份参考脚本、osquery 9 份查询包、Wazuh 4.14.7 的 167 份规则、
  OpenSCAP 0.1.82 的 4 份 Linux datastream、Presidio 2.2.364 的 134 条识别器。
- `/health.suricata` 实测可用，实际签名数 52,270。在线更新采用暂存校验和原子版本切换，
  失败保留旧规则；原文按需加载，规则页支持按引擎搜索和分页。
- Presidio 在线更新接口已通过前端网关实测，成功记录 `rule_source_state` 和审计。
  其余初次下载通过维护命令执行，有磁盘版本清单，但不冒充 API 同步审计记录。
- 告警 #1 / #5 返回对应 DLP / 扫描规则及条件；历史无快照时标识 `current_definition`。
  新检测保存规则原文及 SHA256，优先解释实际命中版本。
- 修复 Zeek JSON 开关、JSON `.log` 解析、Suricata 错误使用 `-q`、Linux cooked-v2 抓包兼容，
  原生命令错误不再吞成空结果。真实 PCAP #2026 原生回放成功；重分析任务 #2080 为 Success，
  解析 38 个包，产生 Zeek Finding #834（`ZEK_WEIRD_001`），已保存规则快照。
- 验证：最新后端定向回归 33 passed / 1 deselected；前端 31 passed，typecheck 与生产构建通过。
  本轮全量后端回归仍有既有 16 项失败（打包、分发、Redis/worker 能力等），不能宣称全量通过。
  `git diff --check` 通过（仅行尾警告）；浏览器工具不可用，未完成截图视觉验收。
- `/test/status` 实测 `present=false`；未调用测试导入、未启用生产 mock、未提交或推送工作区。

边界：下载 Wazuh/osquery/OpenSCAP 规则不等于已在目标机运行，仍需部署或配置对应组件；
Zeek 上游整库脚本不自动执行；Presidio 独立引擎开关未擅自开启，识别器接入已有 DLP 规则库。
这些状态在页面区分为已接入、外部资源、不支持或不完整。Sigma 上游规则要求相应日志来源元数据。

后续独立事项：外部组件部署与凭证配置、修复既有全量测试失败、浏览器视觉验收。

## 历史快照（以下旧 TODO / 未部署描述不再代表当前状态）

### 2026-09-17 会话恢复核验（优先于下方旧快照）

- 已依次重读四个上下文文件，并核对 Git、工作区差异、容器与真实 API。
- `develop` 当前仍为 `ecf8a6f`，领先本地跟踪的 `origin/develop` 4 个提交。
- **告警规则解析已进入运行后端**：容器可加载 16 条 `BUILTIN_RULES`；真实
  `GET /api/v1/alerts/1` 返回 `DLP_TRANSFER_001` 与策略条件，`/alerts/5` 返回
  `NET_SCAN_001` 与 `port_count > 20`。下方“尚未部署、DLP rule=null”记录已过期。
- 未查到关联 `CVE_*` Finding 的现存 Alert，因此本次未完成 CVE 告警 HTTP 验证。
- `GET /api/v1/test/status` 返回 `present=false`，未导入测试数据。
- 工作区另有旧快照未记录的未提交改动：`rules/catalog.py`、`library.py`、`sync.py`、
  多个引擎/适配器规则目录、`api/libraries.py` 的来源/同步接口，以及资产、协议、DLP、
  情报引擎的规则参数接入。运行镜像尚无 `app.rules.catalog`，这批改动未部署。
- `$env:TEMP\bt_full3.txt` 的失败列表与记录的 16 项一致，但文件尾没有汇总行；
  容器 `nostalgic_meitner` 仍在执行挂载工作区的 `pytest -q`，尚无最终结果。
- 下一步先核验这批规则库改动的完整性与测试结果，再决定构建范围；不能把旧测试记录
  当作新增规则库改动的验证结果，也不能按下方旧步骤直接提交全部工作区。

让工具在**全部使用真实数据**的前提下，把「数据安全合规检查服务」相关功能做到演示可用。
本轮两个目标：

1. **导航栏瘦身**：不再为每个引擎单列菜单，全部引擎收敛到**一个**「引擎总览」页。
2. **告警可解释**：看到告警时必须能看到「**命中的规则**」和「**告警匹配到的具体内容**」。

## Requirements

1. 导航栏只保留必要入口，众多引擎放进一个展示栏。
2. 告警详情必须能看到规则与告警匹配的具体内容。
3. 不做演示用假数据，所有数据来自真实链路。
4. 保持既有接口路径 / 返回结构兼容（只做**追加**字段与**新增**查询参数）。

## Completed

### 一、导航收敛为单一「引擎总览」

| 文件 | 修改 |
| --- | --- |
| `frontend/src/router/menu.ts` | 安全引擎组由 12 个逐引擎入口（6 适配器 + 6 平台引擎）改为**唯一** `{ path: '/engines', title: '引擎总览', icon: 'Cpu' }` |
| `frontend/src/router/index.ts` | 新增 `/engines` 路由（置于 `/engines/:name` 之前） |
| `frontend/src/modules/engines/EnginesOverview.vue` | **新文件**：一张表列出全部引擎 —— 中文名 + 引擎 id、类型标签（`bridge` 有值 = 第三方适配器，否则平台内置）、版本、状态、规则文件数、检测数、规则来源、「查看详情」；行点击进 `/engines/<slug>`；另有关键字过滤、3 个 StatCard、刷新；按检测数倒序 |
| `frontend/src/api/engine.ts` | `EngineInfo` 追加 `bridge?: string` |
| `frontend/src/modules/engines/EngineDetail.vue` | 工具栏加「← 引擎总览」 |
| `frontend/src/__tests__/soc.test.ts` | 断言导航含 `/engines`，且**不存在**任何 `/engines/` 开头的子项 |

### 二、告警显示「命中规则 + 命中内容」

**后端**

| 文件 | 修改 |
| --- | --- |
| `backend/app/api/v1.py` | `alert_detail` 追加 `rule` 字段；`_rule_definition(db, rule_id, engine, evidence)` 改为**三层解析**；新增 `import re`；`models` 导入补 `SystemSetting` |
| `backend/app/rules/builtin.py` | **新文件**：`BUILTIN_RULES`（16 条**由引擎代码实现**的规则定义）+ `builtin_rule_definition()` + `dlp_rule_definition()` + `cve_rule_definition()` |

`_rule_definition` 的三层解析顺序：

1. **规则库文件**（原有逻辑，未改）：`app/rules/{logs,data,network,compliance}` 的 YAML/YAR + suricata `.rules`，
   命中 `rule_id` 后解析出 `title/severity/condition/recommendation/detection` 与规则原文。
2. **代码内置规则**（`builtin.py`，新）：`PROTO_*`(4) / `NETWORK_PORT_SCAN` / `NET_C2_BEACON_001` /
   `broad_communication` / `high_packet_rate` / `COMP_WEAK_PROTOCOL_001` / `DATA_PII_001` / `DATA_SECRET_001` /
   `DATA_YARA_001` / `ASSET_PUBLIC_DB_001` / `ASSET_DB_WEAK_AUTH_001` / `ASSET_PUBLIC_WEB_001` / `TI_IOC_001`。
   每条含 `engine/title/severity/condition/recommendation/source`，`source` 指向**真正实现它的 .py 文件**，
   条件文本与引擎代码里的阈值逐条对齐（不是编造的描述）。
3. **数据驱动规则**（新）：
   - `DLP_TRANSFER_001`：从 `system_setting: dlp_policy` 现读现渲染（categories / keywords / fingerprints /
     min_matches / min_confidence），因为 DLP 引擎没有规则文件，它执行的就是策略本身。
   - `CVE_***`：优先读平台本地漏洞库 `local_cves`（实测 394,371 条，来源 grype）取 severity / CVSS /
     published / description，读不到时回退 `finding.evidence.cve`。

**前端**

| 文件 | 修改 |
| --- | --- |
| `frontend/src/components/evidence/RuleMatchPanel.vue` | **新文件**：上半「命中规则」（引擎 / 规则 ID / 规则名 / 等级 / 置信度 / 目标 / **命中条件** / 处置建议 / **规则来源** / 可展开查看规则原文），下半「命中内容」（标量证据键值对，带中文+原始键双标签；`matches`/`queries`/`services`/`dst_ports` 等数组渲染为表格或标签；过滤 `risk_model`/`probe_id` 噪声；值经 `maskSensitiveValue` 脱敏） |
| `frontend/src/modules/operations/alerts/AlertCenter.vue` | 原「检测来源」描述块替换为 `<RuleMatchPanel :rule="detail.rule" :finding="detail.finding" />` |
| `frontend/src/types/alert.ts` | `AlertDetail.rule?: RuleDefinition \| null`，新增导出 `RuleDefinition` |
| `backend/tests/test_alerts.py` | 新增 2 个回归用例；并修复其中一个用例的**执行顺序依赖**（见 Known Issues #2） |

## In Progress

无代码在写。**唯一未完成动作**：重新构建 `source-backend:latest` 并 `--force-recreate source-backend-1`。
本轮后端改动（`builtin.py` + `_rule_definition` 三层解析）**尚未进入运行镜像**，因此线上 `GET /alerts/1`（DLP）
目前仍返回 `rule: null`。

## TODO

- [ ] **重建后端镜像并重启容器**（本轮唯一阻塞项，命令见 `Next Step`）。
- [ ] 重建后实测：`GET /alerts/1`（DLP）应返回 `rule.condition`；任取一条 `threat_intel` 的 CVE 告警应返回 `rule.title = "<CVE> 影响 <service>"`。
- [ ] 全量后端套件**回读结果**（会话 1751 / `$env:TEMP\bt_full3.txt`）确认 16 失败基线、新用例转绿。
- [ ] CRLF 归一化后提交本轮改动，建议信息 `feat(ui,api): one engine overview entry and show the matched rule in alerts`。
- [ ] 把提交号写入本文件 `Task History`，并刷新 `PROJECT_STATUS.md` 的「当前版本 / 前端状态 / API 状态 / 兼容性变更记录」。
- [ ] 决策项（上一轮遗留，用户未回复）：资产详情 IOC 页签在情报库无命中时如何呈现。
- [ ] 决策项（上一轮遗留）：控制台顶部「测试数据 → 导入/清除测试数据」下拉是否在生产构建隐藏。
- [ ] 决策项：是否把 `2026-09-17` 起的 4 个未推送提交推到 `origin/develop`（目前 origin 停在 `e815a54`）。
- [ ] 刷新 `docs/领导演示方案.md` 的数字。
- [ ] `RulesCenter.vue`（`/threat/rules`）页签仍按 `type` 分组，`network/`+`compliance/` 的 YAML 会显示在 Sigma 页签下；数据已带正确 `engine`，页签改造本轮**有意不做**。
- [ ] 可选：发 `v2.10.1` 补丁版本。

## Modified Files

本轮（**未提交**）：

| 文件 | 原因 |
| --- | --- |
| `frontend/src/router/menu.ts` | 安全引擎组收敛为单一「引擎总览」 |
| `frontend/src/router/index.ts` | 新增 `/engines` 路由 |
| `frontend/src/modules/engines/EnginesOverview.vue` | 新增：全部引擎一张表 |
| `frontend/src/api/engine.ts` | `EngineInfo.bridge` |
| `frontend/src/modules/engines/EngineDetail.vue` | 「← 引擎总览」按钮 |
| `frontend/src/components/evidence/RuleMatchPanel.vue` | 新增：命中规则 + 命中内容面板 |
| `frontend/src/modules/operations/alerts/AlertCenter.vue` | 接入 `RuleMatchPanel` |
| `frontend/src/types/alert.ts` | `AlertDetail.rule` / `RuleDefinition` |
| `frontend/src/__tests__/soc.test.ts` | 导航断言改为「有 `/engines`、无 `/engines/` 子项」 |
| `backend/app/api/v1.py` | `alert_detail` 输出 `rule`；`_rule_definition` 三层解析；补 `SystemSetting` 导入 |
| `backend/app/rules/builtin.py` | 新增：代码内置规则目录 + DLP/CVE 定义渲染 |
| `backend/tests/test_alerts.py` | 新增 2 用例 + 修 1 个顺序依赖 |

上一轮已提交的改动见 `Task History`。

## Known Issues

1. **本轮后端改动未进运行镜像**（见 `In Progress`）。前端产物已包含 `引擎总览` 与 `命中内容`（已在
   `source-frontend-1` 的 js 产物中 grep 确认）。
2. **新用例的执行顺序依赖（已修，待全量确认）**：`test_alert_detail_exposes_the_matched_rule_and_its_content`
   单独跑通过、在全量套件里失败（`assert rule is not None` → `None is not None`）。根因：更早的测试留下了
   同 `(rule_id, engine, asset, ioc)` 指纹的 Alert，本用例先删了 `NET_SCAN_001` 的 finding，再 `create_finding_alert`
   就被**抑制**进那条旧 Alert（`alert_service.create_finding_alert` 第 126 行 `existing.finding_id = existing.finding_id or finding.id`
   会保留已删除的 finding_id），于是 `alert_detail` 解析不到 finding → `rule` 为 `None`。修法：用例创建前一并清掉同指纹
   Alert（含 `AlertDelivery`），并补 `assert body["finding"] is not None` 使下次失败更直观。
3. 上一轮遗留：66 条历史告警的 `fingerprint`/`correlation_key` 仍是 `rules` 派生值（只纠正了可见的 `source`）。
4. 上一轮遗留：两个「规则数」口径并存（注册表 = 规则文件数；`/health` = `sid:` 数）。
5. 上一轮遗留：`PROTO_DNS_TUNNEL_001` 证据无主机地址 → 1 条事件仍归 `global`。
6. 完整仓库布局下仍有 16 个环境相关失败用例（基线，见 `Verification`）。

## Verification

### 本轮已执行并记录结果

| 验证 | 命令 / 方式 | 结果 |
| --- | --- | --- |
| 前端类型检查 | `source/frontend` 下 `npx vue-tsc --noEmit` | 通过（exit 0） |
| 前端单测 | `npx vitest run` | 8 文件 / **31 passed** |
| 后端定向用例（本轮新） | 容器内 `pytest tests/test_alerts.py -q` | 8 passed |
| 新代码语法/解析 | 容器内 `ast.parse` + 直接调用 `builtin.*` | `BUILTIN_RULES` 16 条；`PROTO_DNS_TUNNEL_001.title = DNS 隧道 / 异常编码域名`；DLP 条件串含 `min_confidence`；CVE 取到本地库 severity |
| 线上实测（**上一版镜像**） | `GET /api/v1/alerts/5` | `rule.rule_id=NET_SCAN_001`、`title=端口扫描`、`condition=port_count > 20`、`engine=traffic_engine`、`file=scan.yaml`、`content` 144 字符 |
| 线上实测（**上一版镜像**） | `GET /api/v1/alerts/1`（DLP） | `rule = null` —— 正是本轮新增 `dlp_rule_definition()` 要修的点 |
| 前端产物 | `source-frontend-1` 内 grep | `引擎总览`（`index-*.js`、`EngineDetail-*.js`）、`命中内容`（`AlertCenter-*.js`）均存在 |
| 容器状态 | `docker ps` | `source-backend-1` healthy、`source-frontend-1` Up |
| 全量后端套件 | 固定口径 `pytest -q`（输出留档 `$env:TEMP\bt_full3.txt`） | **16 failed / 其余全通过**，16 条与基线逐条一致 → 零回归；本轮新增用例**在套件内已转绿** |

### 未执行

- 浏览器端截图确认：本机 cua 浏览器不可用（`Browsers: unsupported Codex auth method: apikey`），
  改为「接口契约 + 构建产物 grep + 类型检查 + 单测」四重间接验证，未做像素级确认。

### 重要说明：测试基线口径

镜像不包含 `tests/`、`pyproject.toml`、`probe_packages/`，因此必须用固定挂载口径，否则 `pytest` 会因环境缺失产生
16 个失败（`test_package.py` 4 个、`test_distribution.py` 10 个、`test_health`、`test_gap_fixes::test_integrations_...`），
与代码无关：

```powershell
$src = (Resolve-Path ".\00-数据安全工具箱\source").Path
docker run --rm -v "${src}\backend\app:/app/app" -v "${src}\backend\tests:/app/tests" `
  -v "${src}\backend\pyproject.toml:/app/pyproject.toml" -v "${src}\probe:/app/probe" `
  -v "${src}\shared:/app/shared" -v "${src}\probe_packages:/app/probe_packages" `
  -w /app source-backend:latest python -m pytest -q
```

## Next Step

1. 推送远端：本地发布提交与 `v2.11.0` 标签尚未推送，`origin/develop` 仍停在 `e815a54`。
   ```powershell
   git -C "00-数据安全工具箱/source" push origin develop
   git -C "00-数据安全工具箱/source" push origin v2.11.0
   ```
2. 需要在别的机器复现本版时，按 `AGENTS.md` 用 legacy builder 重建 backend / deployment-worker / frontend 镜像；
   探针代码未变，无需重建探针包。
3. 全量后端套件按下方「测试基线口径」的挂载命令复跑，确认 16 项环境失败基线不变、新增用例转绿。

## Task History

| 日期 | 任务 | 结果 | Commit |
| --- | --- | --- | --- |
| 2026-09-18 | 发布 v2.11.0（引擎规则库 + PCAP 工作台） | 完成：版本号、CHANGELOG、标签、状态文档 | tag `v2.11.0` |
| 2026-09-18 | PCAP 工作台修复（上传定位、包列表分页、传输文件提取与文本/Hex 预览） | 完成并部署验证 | 随 v2.11.0 发布 |
| 2026-09-17 | 导航收敛为单一「引擎总览」+ 告警显示命中规则与命中内容（含代码内置规则目录、DLP 策略与本地 CVE 库解析） | 完成并随 v2.11.0 发布 | 随 v2.11.0 发布 |
| 2026-09-17 | 安全引擎规则归属修复（幽灵引擎 `rules`）+ 引擎下拉/规则显示改读注册表 + 真实数据归属纠正 | 完成并部署验证，零回归 | `573d9e9` / `ecf8a6f` |
| 2026-09-17 | 资产归属根因修复 + 事件归属重算端点 + 回归用例 | 完成并部署验证，零回归 | `0cf03de` / `8d0c3c8` |
| 2026-09-17 | 探针远程卸载（含生产文件清理，E2E 零残留） | 完成并发布 | `735a657` / `3967e82` (v2.10.0) |
| 2026-09-17 | 下发/回收各阶段中文标签 + 演示方案文档 | 完成 | `2ff8390` |
| 2026-09-17 | 前端三处可见缺陷 + 资产详情关联查询 | 完成，46 端点全 200 | `e815a54` |
| 2026-09-17 | 建立 `AGENTS.md` / `TASK.md` / `PROJECT_STATUS.md` / `docs/architecture.md` | 完成 | （`e815a54` 之后） |

### 上一轮详情（安全引擎规则归属，`573d9e9` / `ecf8a6f`）

问题：「安全引擎的规则是不是都正确匹配到了规则，为什么规则的显示都是空？」三个根因：

1. `backend/app/rules/interpreter.py::interpret_rules()` 硬编码 `engine="rules"`（注册表里不存在的幽灵引擎），
   而 `TrafficEngine` 与 `ComplianceEngine` 都调用它 → 78 条网络规则检测挂在幽灵引擎下、引擎页过滤全为 0、
   66 条告警 `source='rules'`。修复：引擎名由调用方传入 `self.name`。
2. 前端三处引擎下拉是硬编码且与 `detection_findings.engine` 真实取值对不上（`EngineDetail.vue`、`DetectionCenter.vue`、
   `SensitiveDiscovery.vue` 用 `'data'` 而非 `'data_engine'`）→ 所有过滤为空。修复：`GET /engine/registry` 追加
   `slug`/`label`/`rule_count`/`detection_engine`/`detection_count`，前端全部改读注册表。
3. `EngineDetail.vue` 用 `health[name].rule_count` 覆盖真实规则数，而 `/health` 只有 tshark/zeek/suricata 三个键 →
   其余引擎规则数渲染成空。修复：规则数与规则清单统一由注册表 + `GET /rules?engine=` 提供；
   同时修掉 `workers/tasks.py::_worker_capability()` 里 suricata 恒为 0 的假 0（改为按实际加载的规则文件统计）。

真实数据归属纠正（只改 engine 字段，不增删记录、不改 fingerprint）：`detection_findings` 79 行 `rules`→`traffic_engine`、
18 条事件的 `findings.items[*].engine`、66 条 `alerts.source`。正向验证：用真实 PCAP（pcap 1807）重新分析
（任务 #1852 Success）→ 新 finding id=820 `engine=traffic_engine`，证明新代码不再产生 `rules`。

线上真实取值：`protocol_engine` 375、`threat_intel` 332、`traffic_engine` 98、`dlp_engine` 14、`compliance_engine` 1；
`/dashboard/engines` 合计 820 = `detection_findings` 总数；库内 `engine='rules'` 已归零。

### 更早详情（资产归属修复，`0cf03de` / `8d0c3c8`）

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
5. **findings 去重签名**：`workers/tasks.py::_finding_signature()` 旧实现只看 `src_ip/dst_ip/asset`，对流量引擎 findings
   恒为空串，会把不同主机的 findings 误合并；现复用同一套身份解析。

归属重算实测：`POST /api/v1/incidents/rebuild-attribution` 首次
`scanned=54, recovered=50, relabelled=53, globals_before=16, globals_after=0, hosts=33`；
再跑一次（幂等）`scanned=55, recovered=1, globals_before=2, globals_after=1`。

同期完成：前端可见缺陷 3 项（`e815a54`）、`docs/领导演示方案.md`、v2.10.0 探针远程卸载闭环、四个上下文文件、
核实库内无测试数据（`GET /api/v1/test/status` → `present=false`）。
