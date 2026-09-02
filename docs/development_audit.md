# 后端开发审计报告

审计日期：2026-09-02

审计分支：`develop`

审计范围：`backend/app`、`backend/tests`、`backend/workers`、`backend/alembic`

## 1. 当前完成度

| 模块 | 状态 | 说明 |
|---|---|---|
| 资产识别 | 基础可用 | 基于端口/服务名/关键词分类，缺少指纹、banner、弱认证、公网暴露证据链 |
| 元数据分析 | 基础可用 | JPG/PNG/PDF/DOCX、SHA256、EXIF、隐藏信息，缺少数据库 schema/column 级分析 |
| 算法评估 | 基础可用 | 熵、NIST STS 子集、简单分类模型评估 |
| PCAP 协议分析 | 可用 | tshark 优先、dpkt 回退，支持协议分布、五元组、会话；缺少 TCP 重组、TLS/JA3、DNS/HTTP 深度分析 |
| 流量异常 | 基础规则 | 端口扫描、大流量、包速率；高包速率存在 `max(...,1)` 阈值缺陷 |
| 安全审计 | 基础可用 | 文件/资产/泄露/网络/日志摘要；日志检测为关键词正则，误报明显 |
| 任务系统 | 可用 | Celery worker、pending/running/success/failed |
| 报告系统 | 可用 | HTML/PDF/CSV，PDF 在 Docker 内验证通过 |
| 测试 | 基础可用 | 后端 22 项测试通过；缺少 engine 单元测试、集成测试、benchmark |

当前代码量：23 个后端 Python 文件，约 1576 行；9 个测试文件，约 204 行。

## 2. 架构问题

1. **无统一检测引擎接口**

   当前检测能力散落在 `services/*.py`，没有统一 `DetectionEngine`、`DetectionContext`、`DetectionResult`。后续增加 Suricata、YARA、Sigma、Presidio 时难以扩展。

2. **检测结果无统一结构**

   文件、资产、PCAP、日志返回结构不一致，缺少统一的 `engine`、`rule_id`、`severity`、`confidence`、`evidence`、`recommendation`、`timestamp`。

3. **无统一风险评分模型**

   `risk_level` 由各服务独立计算，未融合资产权重、暴露因子、数据敏感等级、威胁因子、置信度。

4. **规则没有数据化**

   网络异常、日志检测规则硬编码在 Python 中，无法扩展、维护和版本管理。

5. **worker 只调用旧 service**

   `analyze_pcap_task`、`metadata_task`、`asset_task` 直接调用旧服务，未接入 pipeline/engine registry。

6. **数据模型不完整**

   缺少 engine result、detection rule、vulnerability、data asset、threat intel、graph relation、compliance check 等模型。

## 3. 缺失功能

- TCP Stream 重组、request/response、payload 统计
- TLS JA3/JA4、证书分析、异常 TLS 指纹
- DNS tunneling、高熵域名、DGA、TXT 异常
- HTTP 异常 User-Agent、WebShell/C2、文件上传检测
- Suricata ET/ET Open 规则解析与 `eve.json` 统一事件模型
- Zeek `conn.log`、`dns.log`、`http.log`、`ssl.log`、`files.log` 统一事件模型
- Sigma 规则转换与日志检测
- YARA 文件/payload 检测
- CVE/CWE/NVD 资产漏洞关联
- PII/NER 敏感数据识别、数据分类、数据资产地图
- 数据库 schema/table/column 自动识别
- 资产关系图与风险传播
- 统一风险评分与 Critical/High/Medium/Low 输出
- 合规检查引擎
- Benchmark（正常、扫描、C2、数据泄露、敏感样本）
- 每个 engine 的单元测试、集成测试

## 4. 技术债务

1. `traffic_service.detect_anomalies` 中 `max(duration, 1)` 导致短时高包速率永远不触发。
2. `audit_service.log_analysis` 使用无边界正则：
   - `syn` 匹配 `syntax`，造成 SQL 错误误报端口扫描
   - `admin` 匹配普通用户名，造成认证失败误报权限提升
3. `api/v1.py` 集中 30+ 路由，文件过大，缺少 API 分层和权限边界。
4. `metadata_service`、`protocol_service` 仍保留宽泛 `except Exception`，错误证据不足。
5. 报告模板直接读取全部资产/文件/PCAP，缺少分页和大型数据保护。
6. 旧 `asset_service` 与 `metadata_service` 在升级后需要兼容层，不能直接删除已有功能。

## 5. 重构计划

### Phase A：统一引擎框架

- 新建 `engine/core`：`DetectionEngine`、`DetectionContext`、`DetectionResult`、`EngineRegistry`、`Pipeline`
- 所有新检测器通过 `analyze(context) -> DetectionResult`
- 旧 service 通过适配器接入，避免删除已有能力

### Phase B：规则数据化

- 新增 `rules/network`、`rules/data`、`rules/compliance`、`rules/logs`
- 使用 YAML 描述规则，新增规则解释器
- 日志检测改为 Sigma 风格规则 + 兼容旧正则

### Phase C：专业引擎

- `asset_engine`：banner/nmap/tshark/socket probe、服务指纹、公网 Redis、弱认证风险
- `protocol_engine`：TCP 重组、TLS、DNS、HTTP 分析
- `traffic_engine`：规则驱动异常检测，修复高包速率阈值
- `data_engine`：PII regex、熵、Presidio、YARA、数据资产地图
- `risk_engine`：统一评分模型
- `compliance_engine`：基础合规检查
- `threat_intel`：CVE/CWE/NVD、IOC、Suricata/Zeek 事件

### Phase D：任务与报告

- worker 接入 pipeline
- 报告包含资产、风险排行、攻击行为、敏感数据、漏洞、整改建议

### Phase E：测试与验收

- 每个 engine 单元测试
- PCAP → 解析 → 检测 → 风险评分 → 报告集成测试
- 正常、扫描、C2、数据泄露、敏感数据 benchmark

## 6. 审计结论

当前版本是“可运行的安全分析工具框架”，核心链路真实可跑，但距离企业级数据安全检测平台仍有明显差距。主要缺口不是基础设施，而是检测能力缺少统一引擎、规则数据化、敏感数据识别、风险融合和完整证据链。

