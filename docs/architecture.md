# 架构

系统由三部分组成：

1. Probe Agent：单进程、低资源，只负责采集与上传
2. Backend Analysis Platform：FastAPI + Celery + PostgreSQL + Redis，负责分析、调度、存储、报告
3. Vue Management Console：Vue 3 + Element Plus + ECharts，负责统一管理

分析链路：

`Probe 采集 -> 上传文件/资产/PCAP -> Celery 任务 -> 后端分析服务 -> PostgreSQL 存储 -> 前端展示 -> 报告生成`

Zeek/Suricata 通过 `EXTERNAL_ENGINE_DIR` 提供可选外部引擎通道，默认核心解析使用 tshark/dpkt。

## 统一检测引擎

所有检测器实现 `DetectionEngine.analyze(context) -> list[DetectionResult]`，通过 `EngineRegistry` 注册，由 `DetectionPipeline` 统一调度。

检测结果统一包含：`engine`、`rule_id`、`severity`、`confidence`、`evidence`、`recommendation`、`timestamp`、`risk_score`、`risk_level`。

风险评分公式：

`base = severity_weight * 20`

`risk_score = min(100, base * exposure_factor * data_sensitivity * threat_factor * confidence)`
