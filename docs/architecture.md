# 架构

系统由三部分组成：

1. Probe Agent：单进程、低资源，只负责采集与上传
2. Backend Analysis Platform：FastAPI + Celery + PostgreSQL + Redis，负责分析、调度、存储、报告
3. Vue Management Console：Vue 3 + Element Plus + ECharts，负责统一管理

分析链路：

`Probe 采集 -> 上传文件/资产/PCAP -> Celery 任务 -> 后端分析服务 -> PostgreSQL 存储 -> 前端展示 -> 报告生成`

Zeek/Suricata 通过 `EXTERNAL_ENGINE_DIR` 提供可选外部引擎通道，默认核心解析使用 tshark/dpkt。
