# 最终自审

## 1. 哪些设计已经实现？

- 统一 DetectionEngine Interface：`engine/core/base.py`
- 统一 DetectionResult：`engine/core/result.py`
- EngineRegistry / DetectionPipeline：`engine/core/registry.py`、`engine/core/pipeline.py`
- 资产引擎：服务指纹、公网数据库、弱认证
- 协议引擎：TCP 流重组、TLS/JA3 字段、DNS 高熵/隧道、HTTP UA/上传
- 流量引擎：YAML 规则解释器、端口扫描、高包速率、C2 Beacon
- 数据引擎：PII regex、密钥熵、YARA、Presidio 可选、数据资产地图
- 风险引擎：资产权重 × 暴露因子 × 数据敏感度 × 威胁因子 × 置信度
- 合规引擎：公网数据库、弱协议
- Sigma 风格日志引擎
- 威胁情报：IOC + NVD CVE API
- 统一数据库模型：DetectionFinding、Vulnerability、DataAsset、GraphRelation
- 报告系统：PDF/HTML 包含资产、检测结果、数据资产、整改建议
- Docker：后端镜像包含 tshark、nmap、suricata、YARA、WeasyPrint
- 测试：35 项后端测试通过，前端构建与测试通过，Benchmark 通过

## 2. 哪些功能仍不足？

- Presidio 为可选依赖，默认镜像未安装大型 NLP 模型
- Zeek 未作为默认镜像组件安装，仅保留二进制检测路径
- CVE/NVD 依赖公网 API，离线环境需要本地漏洞库适配
- 资产关系图目前为结构化节点/边，尚未实现可视化图渲染
- TLS JA3/JA4 依赖 tshark 字段，未实现完全独立的 TLS 指纹计算器
- 合规规则仍是基础级，未覆盖等保/GDPR/PIPL 全量条款

## 3. 是否存在伪实现？

没有 mock。所有检测结果都来自真实输入：

- 文件：真实文件解析、regex、熵、YARA、Presidio（可选）
- PCAP：真实 tshark/dpkt 解析
- 日志：Sigma 规则匹配
- 资产：banner/socket/nmap/tshark 证据
- 风险：基于统一评分公式计算
- 报告：Jinja2 + WeasyPrint 真实生成 PDF

## 4. 是否存在安全逻辑漏洞？

已发现并修复/规避：

- 旧高包速率规则因 `max(..., 1)` 无法触发，现由规则解释器使用 0.001 秒分母
- 旧日志关键词存在 `syn/syntax`、`admin` 误报，新增 Sigma 规则并保留旧规则兼容
- SQLite 嵌套会话锁已修复，改为复用调用方 Session
- 文件路径使用白名单保存，避免路径穿越

仍需关注：

- 未启用认证，`/api/v1` 当前为内网开放
- NVD API 调用需要网络和限流保护
- 大文件/大 PCAP 需要分页与资源限制

## 5. 是否达到企业数据安全平台最低要求？

核心检测链路已达到企业平台的最低要求：可运行、可测试、有输入输出、有检测证据、有风险解释、有自动化测试、有 Docker 部署和统一报告。

若要用于正式生产，建议下一步补充认证授权、离线漏洞库、Zeek 镜像、Presidio 模型、可视化关系图和合规规则库。

