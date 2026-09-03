# 前端缺口记录 (Frontend Gap Log)

> 前端优先建设策略。以下为前端需要但后端尚未提供的能力。
> 遵循约定：页面需要后端不存在的数据时，必须在此记录；后端补齐后移除对应条目。

> **状态更新（2026-09-04）**：除个别边界外，下表 1-16 项后端均已补齐并接入前端，
> 详见 [docs/acceptance_test_report.md](acceptance_test_report.md)。新发现的独立缺口见文末。

---

## 1. PCAP 数据包详情（最高优先级）

Feature: Packet Explorer / Protocol Tree / Raw Viewer
页面: PCAP Workbench → Packets
需求: 三栏布局中，中间栏展示数据包协议分层树（Ethernet / IPv4 / IPv6 / TCP / UDP / HTTP / DNS / TLS），右侧栏展示原始字节（Hex + ASCII）。
当前接口: `GET /pcaps/{id}/packets`（仅返回 number/timestamp/src/dst/protocol/length/info，无原始字节与分层字段）
缺少字段: `raw`（原始字节）、`layers`（协议分层结构，含各层字段）
需要新增接口: `GET /pcaps/{pcap_id}/packets/{packet_id}` 返回 `{ packet, raw, layers }`；或扩展 `GET /pcaps/{id}/packets` 返回上述字段
优先级: P0

---

## 2. Live Traffic 实时指标

Feature: Live Traffic / 实时网络
页面: Network Analysis → Live Traffic
需求: 在线 Probe、当前连接数、Packet/s、Byte/s、Top Source、Top Destination、Top Port、实时告警。
当前接口: `/health`、`/probes`、`/pcaps`、`/alerts/stream`（无实时流量指标端点）
缺少字段: 实时 pps、bps、连接数、Top 源/目的/端口
需要新增接口: `GET /network/live` 或基于 probe 心跳的实时指标端点（如 `GET /probes/{id}/metrics`）
优先级: P1

---

## 3. 全局 Flow Explorer

Feature: Flow Explorer
页面: Network Analysis → Flow Explorer
需求: 跨 PCAP 的全局会话流浏览（源/目的/协议/字节）。
当前接口: 仅 `GET /pcaps/{id}/flows`（按 PCAP 维度）
缺少字段: 全局流聚合
需要新增接口: `GET /flows`（全局流列表，支持搜索/过滤/分页）
优先级: P1

---

## 4. 全局 Protocol Analysis

Feature: Protocol Analysis
页面: Network Analysis → Protocol Analysis
需求: 全局协议分布与协议树（跨全部捕获）。
当前接口: 仅 `GET /pcaps/{id}/protocols`、`GET /pcaps/{id}/traffic`（按 PCAP 维度）
缺少字段: 全局协议聚合
需要新增接口: `GET /protocols`（全局协议统计）
优先级: P2

---

## 5. Sensitive Discovery 聚合端点

Feature: Sensitive Discovery
页面: Asset & Data Security → Sensitive Discovery
需求: 按敏感类目（身份证/手机号/银行卡/Email/医疗数据/Secret）聚合展示敏感发现。
当前接口: `/data/assets`、`/detections?engine=data`、`/risk/summary`（前端聚合，无专用端点）
缺少字段: 类目级敏感命中统计、命中位置
需要新增接口: `GET /sensitive/findings`（类目聚合 + 命中明细）
优先级: P1

---

## 6. Incident Trend 时间序列

Feature: Dashboard 趋势
页面: Dashboard → 趋势
需求: Risk Trend、Detection Trend、Incident Trend 三条趋势线。
当前接口: `GET /dashboard/risk-trend`（含 risk/detection 趋势），无 incident 趋势
缺少字段: incident 按时间序列
需要新增接口: `GET /dashboard/incident-trend`
优先级: P2

---

## 7. MITRE ATT&CK 字段

Feature: Alert Investigation
页面: Alert Center → 右侧调查
需求: 展示 Tactic / Technique / ID。
当前接口: 检测结果 evidence 中无 `tactic` / `technique` / `technique_id` 字段
缺少字段: `evidence.tactic`、`evidence.technique`、`evidence.technique_id`
需要新增接口: 在 DetectionFinding/Incident 序列化中补充 ATT&CK 映射字段
优先级: P2

---

## 8. Alert 关联对象直连

Feature: Alert 关联
页面: Alert Center → 关联
需求: Alert 详情直接返回关联的 Asset、IOC、Data Asset。
当前接口: `GET /alerts/{id}` 返回 finding/incident/probe/pcap/deliveries；Asset/IOC/DataAsset 需从 finding.evidence 推导
缺少字段: `assets`、`iocs`、`data_assets` 关联列表
需要新增接口: 在 `GET /alerts/{id}` 返回中增加 `assets`、`iocs`、`data_assets`
优先级: P2

---

## 9. 规则列表端点（Sigma / Suricata / YARA）

Feature: Rules
页面: Threat Intelligence → Rules
需求: 展示 Sigma、Suricata、YARA 规则及其内容。
当前接口: 仅 `/offline/resources`（含 sigma_rules/suricata_rules 资源元数据），无 YARA，无规则内容
缺少字段: 规则正文内容、YARA 规则
需要新增接口: `GET /rules?type=sigma|suricata|yara`（返回规则列表与内容）
优先级: P2

---

## 10. Sigma 引擎状态

Feature: Security Engines → Sigma
页面: Security Engines → Sigma
需求: 展示 Sigma 引擎状态/版本/规则数。
当前接口: Sigma 为内置规则解释器（`app/rules/sigma.py`），未注册为 integration adapter，无状态端点
缺少字段: Sigma 引擎元数据
需要新增接口: 将 Sigma 纳入 `/integrations` 或新增 `/engines/sigma` 状态端点
优先级: P2

---

## 11. Probe 资源指标

Feature: Probe 详情
页面: Operations → Probe
需求: 展示 CPU、内存、捕获速率、上传速率。
当前接口: Probe 元数据（`extra`）经 heartbeat 可能包含 cpu/memory，但无结构化指标端点
缺少字段: 结构化 cpu/memory/capture/upload 指标
需要新增接口: `GET /probes/{id}/metrics`
优先级: P2

---

## 12. Task Worker 归属

Feature: Task 详情
页面: Operations → Tasks
需求: 展示任务所属 Worker。
当前接口: Task 无 worker 字段
缺少字段: `worker`（执行 Worker 名称）
需要新增接口: 在 `_serialize_task` 中补充 worker 字段
优先级: P3

---

## 13. Asset Vulnerability 数据

Feature: Asset 详情
页面: Asset Center → 详情 → Risk
需求: 展示资产关联的漏洞列表。
当前接口: 存在 `Vulnerability` 模型但无 `/assets/{id}` 关联返回
缺少字段: `vulnerabilities`
需要新增接口: 在 `GET /assets/{id}` 返回中增加 `vulnerabilities`
优先级: P2

---

## 14. Health 引擎规则数

Feature: Health
页面: Operations → Health
需求: 展示各引擎规则数。
当前接口: `/health` 仅返回 tshark/zeek/suricata 的 available/version/rule_count
缺少字段: 全部引擎规则数
需要新增接口: 扩展 `/health` 或 `/integrations` 返回各引擎 rule_count
优先级: P3

---

---

## 15. Follow TCP Stream / Payload 重组

Feature: TCP Stream / Payload
页面: PCAP Workbench → Packets
需求: 选中数据包后支持 "Follow TCP Stream"，按 Client → Server / Server → Client 方向展示 ASCII/Hex 流；支持 TCP Payload 重组与文件恢复入口。
当前接口: `GET /pcaps/{id}/packets`（仅返回摘要字段，无原始字节与流重组）
缺少字段: 流重组数据、方向性负载
需要新增接口: `GET /pcaps/{pcap_id}/streams/{flow_id}` 返回 TCP 流字节；`GET /pcaps/{pcap_id}/files/{file_id}/download` 提供文件恢复
优先级: P1

---

## 16. 文件恢复下载

Feature: Network Files 下载
页面: PCAP Workbench → Files
需求: 对网络文件提供下载与哈希校验。
当前接口: `GET /pcaps/{id}/files`（仅返回文件元数据）
缺少字段: 文件内容下载地址
需要新增接口: `GET /pcaps/{pcap_id}/files/{file_id}/download`
优先级: P2

---

## 变更记录：算法评估模块重构

- 已废弃原"算法评估"三个子模块（随机性评估 / 模型评估 / 性能测试）及其后端接口
  `POST /algorithms/randomness`、`POST /algorithms/evaluate`、`POST /algorithms/performance`（前后端均已移除）。
- 新"算法评估"页面改为两个前端自包含工具（无需后端，5173/5174 同步生效）：
  1. **商用密码应用安全性评估**：依据 GB/T 39786 / GM/T 0001/0002/0004/0005/0024/0054 标准，对密码算法的合规性、正确性、有效性进行评估；采用开源库 `sm-crypto`（SM2/SM3/SM4）做正确性校验，内置弱算法/弱套件/弃用协议规则集。
  2. **代码算法时间复杂度分析**：使用开源解析器 `acorn` 解析 JS/TS AST，结合启发式方法估算时间/空间复杂度（Big-O），支持 Python 启发式分析。

## 汇总

| 缺口 | 页面 | 优先级 | 后端动作 |
|------|------|--------|----------|
| Packet 详情/原始字节 | PCAP Workbench | P0 | 新增 packet-detail 端点 |
| TCP Stream / Payload | PCAP Workbench | P1 | 新增 stream 端点 |
| 文件恢复下载 | PCAP Workbench | P2 | 新增 files download 端点 |
| Live Traffic 实时指标 | Live Traffic | P1 | 新增 live 指标端点 |
| 全局 Flow | Flow Explorer | P1 | 新增 `/flows` |
| 全局 Protocol | Protocol Analysis | P2 | 新增 `/protocols` |
| Sensitive 聚合 | Sensitive Discovery | P1 | 新增 `/sensitive/findings` |
| Incident Trend | Dashboard | P2 | 新增 `/dashboard/incident-trend` |
| MITRE ATT&CK | Alert Center | P2 | evidence 增加 ATT&CK 字段 |
| Alert 关联直连 | Alert Center | P2 | alerts detail 增加关联 |
| 规则列表 | Rules | P2 | 新增 `/rules` |
| Sigma 状态 | Engines | P2 | Sigma 纳入 integrations |
| Probe 指标 | Probe | P2 | 新增 `/probes/{id}/metrics` |
| Task worker | Tasks | P3 | task 增加 worker |
| Asset 漏洞 | Asset Center | P2 | asset detail 增加 vulnerabilities |
| Health 引擎规则数 | Health | P3 | 扩展 health |

> 注：所有缺口均已在对应前端页面以"缺口提示"方式标注，未伪造真实业务数据。

---

## 补全记录（2026-09-04）

- 1 数据包详情/原始字节/分层 → `GET /pcaps/{pcap_id}/packets/{packet_id}`（tshark `-T json -x`）。
- 2 Live Traffic → `GET /network/live`。
- 3 全局 Flow → `GET /flows`。
- 4 全局 Protocol → `GET /protocols`。
- 5 Sensitive 聚合 → `GET /sensitive/findings`。
- 6 Incident Trend → `GET /dashboard/incident-trend`。
- 7 MITRE ATT&CK → 检测序列化增加 `tactic/technique/technique_id`。
- 8 Alert 关联直连 → `GET /alerts/{id}` 增加 `assets/iocs/data_assets`。
- 9 规则列表 → `GET /rules?type=sigma|suricata|yara`。
- 10 Sigma 状态 → `/integrations` 增加 `sigma`。
- 11 Probe 指标 → `GET /probes/{id}/metrics`。
- 12 Task worker → `_serialize_task` 增加 `worker`。
- 13 Asset 漏洞 → `GET /assets/{id}` 增加 `vulnerabilities`。
- 14 Health 引擎规则数 → `/health` 增加 `engine_rule_counts`。
- 15 Follow TCP Stream → `GET /pcaps/{pcap_id}/streams/{stream_id}`（ASCII+Hex）。
- 16 文件恢复下载 → `GET /pcaps/{pcap_id}/files/{file_id}/download`（transient workspace 时 404）。

### 新增缺口：探针文件摄入
探针 `file_loop` 上报的 `file_inventory` 只存入 `probe.extra`，后端无任务将其转为
`FileRecord/DataAsset` 并触发数据引擎。**已由探针直接上传文件内容到 `/files/upload`
解决**（探针 `file_loop` 上传目标文件内容），无需后端新增摄入任务。
