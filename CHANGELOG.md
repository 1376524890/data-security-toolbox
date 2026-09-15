# Changelog

## v2.6.0（feature/network-scan-and-probe-data-assets）

- 修复「资产中心 · 网络扫描」扫不到资产：容器/加固主机上 ICMP+ARP 探测被拦截时 `nmap -sn` 会判定
  `0 hosts up` 并跳过端口扫描。现统一使用 `-Pn -sT`，并新增零依赖的 TCP-connect 扫描引擎兜底
  （无需 root/NET_RAW/nmap，nmap 缺失、被拒或返回空时自动接管），扫描不再受运行环境影响。
- 扫描能力补全：存活发现改为 TCP-connect（`nmap` 仅在 TCP 扫描无结果时作补充）、支持显式端口列表、
  多主机并发（默认 4）、每主机 `--host-timeout` 上限（避免单台过滤主机拖住整个网段扫描）、
  非标准端口被动 banner 识别、HTTP/TLS 指纹。
- 新增网络路径自检：若扫描路径存在透明代理/NAT 拦截（保留地址 192.0.2.1 等被应答），扫描结果会带上
  明确告警，提示改用探针扫描，避免产出不可信资产。
- 「资产中心」扫描面板支持选择扫描来源（平台 / 探针）：指定探针时下发有界的探针侧扫描任务，
  结果经 `POST /probes/{id}/inventory` 回传；扫描进度、引擎、存活主机与服务资产数量均在页面展示。
- 探针数据资产采集：新增探针侧 `[data]` 采集（目录遍历、文件身份、字段推断、敏感类目统计、
  本机数据库服务登记），**仅上传文件名/字段/类目计数，不上传原始数据**；支持定时采集与平台下发任务
  （`POST /probes/{id}/data-assets/jobs`、探针 `POST /probes/{id}/data-assets`，幂等）。
- 「数据资产」页新增「从探针采集数据资产」入口，可按探针筛选，并展示来源探针、主机、路径、
  敏感类目、状态与字段明细。
- 探针部署新增数据资产采集配置（目录/周期/文件上限/深度/数据库服务），生成的 `probe.toml` 增加
  `[scan] allow_remote` 与 `[data]` 段；新增迁移 `0009_probe_data_assets`（`probe_deployments.data_config`）。
- 新增测试：扫描引擎（区间展开、端口选择、TCP 探测、兜底、拦截自检）、探针数据资产采集、
  探针上报入库与任务下发/鉴权、探针部署数据资产配置持久化与 `probe.toml` 生成。

## v2.5.0（feature/v2.2-probe-intel-dlp）

- 探针采集支持所有网卡：Linux 默认 `capture.interface = "any"`，注册/心跳上报各网卡 IPv4/IPv6 及启用状态；部署表单可填写平台任一可达网卡作为回连地址。
- 网络防泄密规则库：展示内置/Presidio/手工规则并可逐条启停；从官方 PyPI 下载并校验 SHA256 导入 Presidio 静态正则（不含 NLP/上下文评分/Python 校验器）；支持手工添加名称、敏感类别与正则，历史 PCAP 可重新分析。
- CVE 漏洞库：支持下载/更新官方 Grype DB v6 与离线导入（`.tar.zst`/`.tar.gz`/tar/SQLite）；在线校验 SHA256、检查 schema、流式分批写入并事务回滚；按 CVE 去重、计算 CVSS 2/3/4 分数，保留手工记录；大库后台导入并显示进度。
- 检查规则中心：支持添加/导入 Suricata 与 YARA 规则；Suricata 校验行、SID 完整性及冲突（运行时可用时执行 `suricata -T`）；YARA 经 yara-python 编译、禁用 include。
- 修复与适配：前端代理上传限制提升至 2 GB（解压 12 GB）以支持 Grype 大文件；探针版本升至 3.2.1，提供 amd64 / arm64 部署包与 SHA256 清单。

## v2.4.0（feature/v2.2-probe-intel-dlp）

- 探针侧资产扫描改为受限、无特权的 TCP connect 扫描：必须显式配置目标，限制主机、端口、并发和总时长；支持管理员下发任务、断线暂存和幂等回传资产清单。
- 新增威胁情报源管理：本地 JSON/CSV 导入导出、IOC 启停、Feodo Tracker、URLhaus 和自建情报源同步；同步任务限流并限制下载体积与记录数。
- 新增旁路网络 DLP：有界 TCP 重组、明文 HTTP/表单/文件对象提取、敏感字段/关键词/SHA256 指纹检测、脱敏证据及覆盖范围说明。
- 修复 `dpkt` 后备解析器将 IPv4 地址以二进制写入 JSON 证据的问题，并兼容 SQLite 无时区时间值的健康检查。
- 更新探针示例、Compose 情报源变量，并新增探针扫描、IOC 规范化和 DLP 脱敏测试。

## v2.3.2（feature/nuclei-integration）

- 修复 PCAP 解析 bug：`dns.resp.len` 等 tshark 字段返回逗号列表时 `int()` 抛
  `invalid literal for int()`；新增 `_first_num` 助手解析首个数值，覆盖
  tcp_streams / app_analysis 相关字段
- 修复 nuclei 扫描入库 bug：`_run_correlations_and_alerts` 返回 `(Alert,bool)`，
  误当 `(alert_id,bool)` 传给 publish_alert；改为 `alert.id`
- 测试数据导入幂等：按 probe+sha256/segment_id 跳过已存在记录，避免
  `uq_pcap_probe_segment` 唯一约束报错
- 新增 test_nuclei / test_protocol(_first_num) 用例；crypto 测试探针名改为唯一


## v2.3.1（feature/nuclei-integration）

- 扫描自动化集成到探针：
  - 探针新增 `[scan]` 配置（enabled / interval_seconds / targets / discovery / top_ports / nuclei / nuclei_tags）
  - 探针 `scan_loop` 定时调用 `POST /api/v1/probes/{id}/scan`（探针鉴权），自动触发 nmap+nuclei 网络环境扫描；
    targets 为空时自动按探针自身 IP 推导 /24
  - 新增 `POST /api/v1/probes/{id}/scan`（探针鉴权）与 `ProbeScanRequest` schema；
    `_is_probe_api` 白名单放行 `/probes/{id}/scan`
  - `probe.toml.example` 补充 `[scan]` 说明


## v2.3.0（feature/nuclei-integration）

- 新增 Nuclei 主动漏洞扫描集成：
  - `nuclei_service`：运行 `nuclei -u <target> -t <templates> -jsonl`，解析结果并归一化为发现
  - `/api/v1/scan` 支持 `nuclei`、`nuclei_tags`、`nuclei_templates` 参数；扫描任务对 nmap 发现的
    HTTP/HTTPS 服务 URL 逐个跑 nuclei，结果进入 detection/alert/incident 流水线（引擎 `nuclei_engine`）
  - 前端「资产中心」扫描面板新增 Nuclei 开关与 tags 输入
  - worker 镜像安装 nuclei 二进制（Dockerfile 下载 + 本地部署时 COPY）
  - 新增 test_nuclei 单测


## v2.2.3

- 新增「测试数据」管理：`POST /api/v1/test/import`（导入手工测试包，标注为 test-demo 探针）、`POST /api/v1/test/clear`（清除测试数据）、`GET /api/v1/test/status`
- 前端头部新增「测试数据」下拉：导入/清除测试数据；导入后设置 sessionStorage，**刷新页面自动清除、恢复原样**
- docker-compose 为 backend 挂载 `data_security_toolbox_manual_testpack`（只读）


## v2.2.2

- 密码评估工具新增「从探针自动识别并填充」：新增 `GET /api/v1/crypto/probe-profile`，聚合探针采集的服务 banner、TLS 握手（cipher suite/JA3/SNI）与无认证信号，自动填充密码算法/套件/协议/密钥长度后评估
  - TLS 十六进制套件 ID 解码为 IANA 名称，识别 CBC/RSA/3DES 等弱套件与 TLSv1.2/1.3 协议
  - 识别服务级密码/认证类型（SSH 主机密钥、MySQL/Redis 认证、TLS）与无认证/匿名访问风险，并入评估发现（GB/T 39786）
  - 画像对算法/套件/协议/密钥长度/密钥管理标注 detected/inferred/default，诚实反映覆盖度



## v2.2.1

- 落实 `docs/gap-analysis.md` 本机可完善项（P0/P1 + Zeek 默认组件）：
  - 新增「安全审计」前端页面（`/audit`，菜单「安全审计」），调用 `/audit/summary`、`/audit/logs`
  - 安全事件中心新增「手工关联」入口（调用 `POST /incidents/correlate`）
  - 检测中心新增「手动流水线」入口（调用 `POST /engine/pipeline`）
  - `/integrations` 读取 worker capability，修复 Zeek/Suricata 在 API 容器视角误报 unavailable；Dockerfile 将 Zeek/Suricata 纳入 API 镜像默认组件
  - 后端 `FileRecord` 持久化 md5（模型/序列化/上传/元数据任务 + alembic 0007 迁移）
  - 修复探针心跳 metadata 互相覆盖：`heartbeat`/`register` 改为深度合并
  - 修复网络文件恢复下载 404：`IntegrationAdapterEngine` 将瞬态工作区提取文件持久化到 `storage/network_files`

## v2.2

- 新增《数据安全工具箱作业指导书》（`docs/数据安全工具箱作业指导书.docx` + `.md`）：按 SIP-Logger 模板结构（封面/修订页/目的/适用范围/职责/安装部署/配置指南/运维管理/升级管理/附录 API）编写，覆盖全部功能点
- 重写 `docs/user-guide.md`：由 6 行精简版扩充为完整使用教程（系统概览、当前服务状态、访问与登录、四条核心使用路径、管理台导航、关键 API 速查、报告、离线部署、常见问题与边界）
- 更新 `CHANGELOG.md`：记录本次文档变更

## v1.0

- 数据资产识别
- 元数据分析
- 算法评估
- PCAP 协议与流量分析
- 安全审计
- 任务系统
- 报告系统
- Docker Compose 部署
- Probe Agent
- Vue 3 管理控制台

## v2.0

- 统一 DetectionEngine 插件化架构
- DetectionContext / DetectionResult / EngineRegistry / Pipeline
- 规则驱动网络检测（YAML）
- TCP 流重组、TLS/DNS/HTTP 深度分析
- C2 Beacon、端口扫描、高包速率检测
- PII/密钥/YARA/Presidio 数据安全检测
- 统一风险评分模型
- 合规检查与威胁情报引擎
- Sigma 风格日志检测
- 数据资产地图与资产关系图
- 专业安全报告（资产、风险排行、敏感数据、检测结果、整改建议）
- Engine 单元测试、PCAP 集成测试、Benchmark

## v2.1

- Incident 真实时间窗口聚类与多 Incident 生成
- Offline Resource Manager：IOC/CVE/Suricata/Sigma/模型真实导入、去重、版本与 manifest
- Integration 完整健康状态与能力元数据
- 统一分页、筛选与关联查询
- Dashboard 风险趋势、Severity、Engine、敏感数据分布
- PCAP Workbench：Overview/Flows/Packets/Protocols/DNS/HTTP/TLS/Files/Alerts
- 管理控制台信息架构、公共组件与设计系统
- 敏感样本统一脱敏
