# Data Security Toolbox

面向企业内网离线环境的数据安全检测与安全审计综合平台。

当前版本采用统一插件化检测引擎：`engine/core` + 资产/协议/流量/数据/风险/合规/威胁情报引擎，检测结果统一输出 `DetectionResult`。

## 能力

- 数据资产识别：主机、IP、服务、数据库资产、敏感数据分类、资产关系与风险等级
- 元数据分析：JPG/PNG/PDF/DOCX 元数据、文件类型、SHA256、隐藏信息检测
- 算法评估：熵值、NIST STS 子集、随机性检测、分类模型评估
- 协议分析：PCAP/PCAPNG 上传、tshark/dpkt 解析、协议分布、五元组、会话分析
- 流量分析：趋势、TopN、协议分布、主机行为画像、异常标记
- 外部引擎：检测到 Zeek/Suricata 时自动解析 conn/dns/http/eve 日志
- 安全审计：文件、资产暴露、敏感数据泄露、网络行为、日志分析
- 任务系统：异步任务、进度、阶段、日志
- 报告系统：HTML/PDF/CSV 报告

## 检测引擎

- `asset_engine`：服务指纹、公网数据库、弱认证、资产风险
- `protocol_engine`：TCP 流重组、TLS、DNS 隧道/高熵、HTTP 异常
- `traffic_engine`：YAML 规则解释器、端口扫描、高包速率、C2 Beacon
- `data_engine`：PII、密钥/Token、YARA、Presidio 可选、数据资产地图
- `risk_engine`：统一风险评分与 Critical/High/Medium/Low
- `compliance_engine`：公网数据库、弱协议合规检查
- `sigma_log_engine`：Sigma 风格日志规则
- `threat_intel`：IOC 与 NVD CVE 查询

## 快速启动

```bash
cp .env.example .env
docker compose up -d --build
docker compose exec backend alembic upgrade head
docker compose exec backend python scripts/seed.py
```

访问 `http://localhost:8080`。

## 离线部署

见 [docs/offline-deployment.md](docs/offline-deployment.md)。

## 分支与版本

见 [docs/versioning.md](docs/versioning.md)。
