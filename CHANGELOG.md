# Changelog

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
