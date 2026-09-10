# 数据安全工具箱 · 功能缺口分析（设计未落地清单）

> 日期：2026-09-04
> 分支：`develop`
> 范围：前端页面/入口、后端接口、外部引擎集成、已知边界
> 说明：本文档归档“已设计但未真正落地”的功能，并区分哪些可在**本机环境**完善、哪些需外部条件。

## 结论摘要

核心检测链路（资产/数据/协议/流量/规则/风险/事件/报告）真实可跑，无 mock。真正“设计了但没落地”的主要集中在三类：

1. 后端/设计已有，但前端缺少页面或入口（安全审计、手工关联、手动流水线）。
2. 外部引擎集成适配器已存在，但当前部署端到端未跑通（Zeek/Suricata 状态不一致，Wazuh/osquery/OpenSCAP 缺依赖）。
3. 文档明确标注的边界/未实现（HTTPS 解密、MD5 未存储、文件下载 404、探针心跳覆盖、Presidio/CVE/合规等）。

---

> **实施状态（2026-09-04 更新）**：本节 P0/P1 本机可完善项已全部落地并通过本地测试（后端 124 项 pytest 全绿，前端 `vue-tsc` + `vite build` 通过）。已实现：安全审计前端页面、手工事件关联 UI、手动触发流水线 UI、Zeek/Suricata 引擎状态一致（`/integrations` 读取 worker capability）、MD5 后端存储、文件恢复下载 404 修复（瞬态工作区文件持久化）、探针心跳 metadata 合并、Zeek 作为默认镜像组件。详见下文各表标注。

## A. 后端/设计有，但前端没有页面或入口

| 功能 | 现状 | 证据 |
|------|------|------|
| 安全审计 | 后端有 `POST /audit/logs`、`GET /audit/summary`；前端有 `api/audit.ts`（`analyzeLog`/`getAuditSummary`），但**无任何 Vue 页面/路由/菜单使用** | `rg` 全前端无 `.vue` 引用 audit；README 列“安全审计”于“威胁与检测”，前端菜单无该项 |
| 手工事件关联 | 后端有 `POST /incidents/correlate`，前端 **0 处调用** | 自动关联已实现，手工关联无 UI 入口 |
| 手动触发检测流水线 | 后端有 `POST /engine/pipeline`，前端 **0 处调用** | 流水线只能由上传/任务自动触发 |

## B. 外部引擎集成（适配器有，端到端未跑通）

`/api/v1/integrations` 实测（2026-09-04）：

| 引擎 | enabled | healthy | status | 说明 |
|------|---------|---------|--------|------|
| zeek | true | false | unavailable | `Zeek binary not found`（API 容器无二进制，worker 容器有） |
| suricata | true | false | unavailable | `Suricata binary not found`（同上） |
| wazuh | true | false | unavailable | `Wazuh API not configured; offline parser available`；本机 ARM64 跑不动 amd64 镜像 |
| osquery | false | false | unavailable | `osquery binary or socket not configured` |
| openscap | true | false | unavailable | `OpenSCAP scanner not found` |
| presidio | true | true | ready | 已健康 |
| misp | true | true | ready | 离线 IOC store 可用；MISP API 未配置 |
| sigma | true | true | ready | 内置 Sigma 风格日志规则解释器 |

**关键不一致**：Zeek/Suricata 二进制在 **worker 容器**可用（`/health` 的 `worker_capabilities` 显示 available），但 **API 容器**没有，导致 `/integrations`（API 容器视角）报不可用。引擎详情页读到的是 API 容器状态，因此显示 unavailable。

## C. 已知边界 / 未实现功能

| 功能 | 现状 | 出处 |
|------|------|------|
| HTTPS / TLS 解密 | 未实现；无 SSLKEYLOGFILE/密钥日志，仅采集 TLS 握手元数据（SNI/cipher/JA3） | README / acceptance_test_report §7.2 |
| MD5 | 探针计算 SHA256；后端 `FileRecord` 未存 md5（`file_records` 表有 md5 字段，后端不落） | README / acceptance_test_report §7.3 |
| 文件恢复下载 | `GET /pcaps/{id}/files/{file_id}/download` 在 transient workspace 时 404 | frontend-gap 补全记录 |
| 探针心跳覆盖 | 多循环（heartbeat/asset/file）互相覆盖 `probe.extra`，导致 `/probes/{id}/metrics` 的 `capture_tool/cpu` 有时为空 | README / acceptance_test_report §7.1 |
| Presidio 模型 | 默认关闭，首次调用需下载数百 MB spaCy 中文模型 | final_review §2 |
| CVE / NVD | 依赖公网 API；离线环境缺本地漏洞库（`/offline/cves` 仅离线清单） | final_review §2 |
| Zeek 默认镜像组件 | 未作为默认镜像组件安装，仅保留二进制检测路径 | final_review §2 |
| TLS JA3/JA4 独立指纹计算器 | 依赖 tshark 字段，未实现完全独立的指纹计算器 | final_review §2 |
| 合规规则 | 基础级，未覆盖等保/GDPR/PIPL 全量条款 | final_review §2 |

## D. 已实现、避免误判

- **资产关系图 / 攻击链图**：`AttackGraph.vue` 用 `@vue-flow` 真实渲染（资产中心内），后端 `/graph`、`/assets/{id}` 有数据 → 已实现，只是嵌在资产详情而非独立菜单页。
- **登录 / 认证**：已启用（访问接口返回 `admin authentication required`）。`final_review.md` 中“未启用认证”为旧结论。
- **frontend-gap 1–16 项**：后端均已补齐（`/packets/{pid}`、`/streams/{sid}`、`/flows`、`/protocols`、`/sensitive/findings`、`/rules`、`/probes/{id}/metrics` 等均存在）。

---

## E. 本机环境可完善性清单

| 功能 | 本机可完善 | 所需动作 | 依赖 |
|------|-----------|----------|------|
| 安全审计前端页面 | ✅ 已实现 | 新增 Vue 页面/路由，调用 `/audit/summary`、`/audit/logs` | 无 |
| 手工事件关联 UI | ✅ 已实现 | 新增按钮/弹窗，调用 `POST /incidents/correlate` | 无 |
| 手动触发流水线 UI | ✅ 已实现 | 新增入口，调用 `POST /engine/pipeline` | 无 |
| Zeek/Suricata 引擎状态一致 | ✅ 已实现 | 将 zeek/suricata 装入 API 镜像，或让 `/integrations` 读取 worker capability | 重建 backend 镜像 |
| MD5 后端存储 | ✅ 已实现 | 后端 `FileRecord` 写入 md5（探针已上报 md5） | 无 |
| 文件恢复下载 404 修复 | ✅ 已实现 | 后端修复 transient workspace 下载 | 无 |
| 探针心跳 metadata 合并 | ✅ 已实现 | 后端 heartbeat 改为合并 metadata 而非整体替换 | 无 |
| Zeek 作为默认镜像组件 | ✅ 已实现 | Dockerfile 安装 Zeek | 重建镜像 |
| osquery 集成 | ⚠️ 可完善但需额外组件 | 安装 osquery 二进制/配置 `OSQUERY_SOCKET`，或走离线解析 | 安装 osquery |
| OpenSCAP 集成 | ⚠️ 可完善但需额外组件 | 容器安装 `openscap-scanner`，或走离线解析 | 安装 oscap |
| Wazuh 集成 | ⚠️ 本机仅能接通适配器/离线解析（设 `WAZUH_URL`）；真正运行需外部 x86 或 arm64 镜像 | 本机 ARM64 跑不动 amd64 镜像 | 外部 x86 / arm64 镜像 |
| Presidio 中文模型 | ⚠️ 可完善但需下载模型 | 设 `PRESIDIO_ENABLED=true` 并预置 spaCy 模型 | 下载数百 MB 模型 |
| 合规规则扩充 | ⚠️ 可完善但需编写规则内容 | 扩充 `rules/compliance` | 规则内容 |
| HTTPS / TLS 解密 | ❌ 本机难完善 | 需 TLS 密钥/实现解密，属较大功能开发 | 外部条件 / 大开发 |
| CVE / NVD 本地漏洞库 | ❌ 本机难完善 | 需离线漏洞库数据源（NVD/CVE 全量） | 外部数据源 |
| TLS JA3/JA4 独立计算器 | ❌ 本机难完善 | 需实现独立指纹计算器 | 开发实现 |

## F. 建议优先级

1. **P0（已完成）**：Zeek/Suricata 引擎状态一致；安全审计前端页面。
2. **P1（已完成）**：MD5 后端存储；文件恢复下载 404；探针心跳 metadata 合并。
3. **P2（本机可做，需额外组件/资源）**：osquery / OpenSCAP / Presidio 模型 / Wazuh 接通（离线解析）；合规规则扩充。
4. **P3（需外部条件或大开发）**：HTTPS/TLS 解密；CVE/NVD 本地库；TLS JA3/JA4 独立计算器。

---

## G. 开源组件选型建议（三项难完善项）

> 结论：HTTPS/TLS 解密、CVE/NVD 本地库、TLS JA3/JA4 独立指纹计算器均可采用**开源组件**接入。
> 三者均为 Python / 纯 Python，`pip` 可在本机 ARM64 安装，许可均为宽松开源（MIT / Apache-2.0），可放心并入。

### G.1 HTTPS / TLS 解密

| 开源组件 | 许可 | 方式 | 集成点 | 说明 |
|----------|------|------|--------|------|
| **tshark / Zeek + SSLKEYLOGFILE**（项目已装 tshark、worker 有 Zeek） | GPL-2.0 / BSD | 被动解密 | 后端分析侧 | 只需端点提供 TLS 会话密钥（`SSLKEYLOGFILE`），无需 MITM，最不侵入；加 `keylog_file` 配置即可解密 |
| **mitmproxy** | MIT | 主动 MITM | 探针/采集侧 | 生成 CA 证书、拦截并解密 HTTPS；需端点信任 CA、改变流量，适合受控环境 |
| BetterCap | GPL-3.0 | 主动 MITM | 采集侧 | mitmproxy 的替代，功能更偏渗透 |

**建议**：优先落地**被动 SSLKEYLOGFILE** 路径（改配置 + 复用现有 tshark/Zeek），主动 MITM（mitmproxy）作为可选采集组件。对纯网络捕获，JA3/JA4 检测通常比解密更实用。

### G.2 CVE / NVD 本地漏洞库

| 开源组件 | 许可 | 集成点 | 说明 |
|----------|------|--------|------|
| **NVD JSON feeds**（官方） | 公开数据 | 本地 CVE 存储 | 下载全量 JSON 入库，配合查询库做资产→CVE 关联 |
| **cve-bin-tool**（Intel） | MIT | 匹配引擎 | 内置 NVD/CVE 数据，支持**离线库**，可做软件→CVE 匹配 |
| **trivy / grype** | Apache-2.0 | 独立扫描器 | 容器/SBOM 漏洞扫描，可导出/导入**本地 DB** 离线用 |
| OSV.dev | Apache-2.0 | 漏洞数据源 | 开源软件漏洞库，支持离线镜像 |

**建议**：把现有 `/offline/cves` 扩展为**本地 CVE 库 + 匹配引擎**（用 NVD feeds 或 cve-bin-tool 离线 DB），在离线环境做资产漏洞关联。注意全量库达数 GB，需定期镜像更新。

### G.3 TLS JA3 / JA4 独立指纹计算器

| 开源组件 | 许可 | 集成点 | 说明 |
|----------|------|--------|------|
| **ja3**（Salesforce） | MIT | `protocol_engine` | 解析 ClientHello 计算 JA3/JA3S |
| **ja4**（FoxIO） | MIT / Apache-2.0 | `protocol_engine` | 更健壮、兼容 TLS 1.3，**推荐替代/补充 JA3** |
| scapy / tls-parser | GPL / BSD | 原始 TLS 解析 | 从原始字节提取 ClientHello |

**建议**：将 **ja3 + ja4** 作为 Python 依赖接入 `protocol_engine`，从原始 ClientHello 独立计算指纹。这样即使无 tshark（走 dpkt 回退）也能计算，并补上项目目前缺少的 JA4（现状仅依赖 tshark 的 `tls.handshake.ja3` 字段）。

### G.4 本机可行性

- **JA3/JA4**：✅ 最易做，改 `protocol_engine` + 加依赖即可。
- **TLS 解密（SSLKEYLOGFILE 被动路径）**：✅ 改配置 + 用现有 tshark，成本低；主动 MITM（mitmproxy）需额外采集组件。
- **CVE/NVD 本地库**：⚠️ 可行但数据量大（数 GB），需一次下载 + 定期更新，属“本机可做、需外部数据源镜像”。
