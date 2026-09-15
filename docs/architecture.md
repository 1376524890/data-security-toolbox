# 架构

系统由三部分组成：

1. Probe Agent：单进程、低资源，只负责采集与上传
2. Backend Analysis Platform：FastAPI + Celery + PostgreSQL + Redis，负责分析、调度、存储、报告
3. Vue Management Console：Vue 3 + Element Plus + ECharts，负责统一管理

分析链路：

`Probe 采集 -> 上传文件/资产/PCAP -> Celery 任务 -> 后端分析服务 -> PostgreSQL 存储 -> 前端展示 -> 报告生成`

职责边界：探针只在被监控主机执行采集、PCAP/文件分片上传、心跳、资产盘点和受控命令；不执行服务端风险评分、告警关联或报告生成。FastAPI 服务端负责探针注册鉴权、接收和持久化原始数据、创建任务及提供查询 API；Celery worker 负责调用检测引擎、RiskEngine、IncidentEngine 并回写 DetectionFinding/Alert/Incident；Vue 前端只负责登录、配置、任务状态和结果展示。数据通过 `X-Probe-ID`/`X-Probe-Token` 标识探针，原始数据进入 PostgreSQL/文件存储，任务通过 Redis 投递，分析结果再由 API 返回前端。

组件位置检查：

| 组件 | 执行位置 | 输入 | 输出 |
| --- | --- | --- | --- |
| 探针采集、TCP 盘点、心跳 | 受监控主机 Probe | 本机流量/文件/资产 | 上传任务、资产元数据 |
| FastAPI 接入与鉴权 | backend | 探针 HTTP、前端 HTTP | 数据入库、Celery 任务 |
| tshark/dpkt、Zeek、Suricata、Nuclei | worker（部分工具由 API 镜像提供状态探测） | PCAP/扫描目标/适配器数据 | DetectionResult |
| Sigma、协议、流量、数据、资产、威胁情报引擎 | worker | DetectionContext | DetectionResult |
| RiskEngine、IncidentEngine、告警 | worker | DetectionResult/历史结果 | Finding、Incident、Alert |
| Vue + nginx | frontend | API 返回数据 | 管理界面 |

Zeek/Suricata 通过 `EXTERNAL_ENGINE_DIR` 提供可选外部引擎通道，默认核心解析使用 tshark/dpkt。

V2.1 新增 `Integration Adapter Layer`，统一第三方组件输入：

`第三方工具输出 -> IntegrationAdapter -> DetectionResult -> RiskEngine -> DetectionFinding`

适配器包括 Zeek、Suricata、Presidio、MISP、osquery/Wazuh、OpenSCAP。事件关联由 `incident_engine` 对多个 Finding 按时间、资产、IOC、攻击链聚合为 Incident。

## 统一检测引擎

所有检测器实现 `DetectionEngine.analyze(context) -> list[DetectionResult]`，通过 `EngineRegistry` 注册，由 `DetectionPipeline` 统一调度。

检测结果统一包含：`engine`、`rule_id`、`severity`、`confidence`、`evidence`、`recommendation`、`timestamp`、`risk_score`、`risk_level`。

风险评分公式：

`base = severity_weight * 20`

`risk_score = min(100, base * exposure_factor * data_sensitivity * threat_factor * confidence)`
