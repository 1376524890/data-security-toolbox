# API 概览

FastAPI 启动后可在 `http://localhost:8000/docs` 查看 OpenAPI 文档。

主要接口前缀：`/api/v1`

- `POST /probes/register` 注册探针
- `POST /probes/{id}/heartbeat` 探针心跳
- `POST /scan` 主动扫描（平台或指定探针，支持 `ports` 显式端口）
- `GET /scan/{task_id}` 扫描进度与结果
- `POST /probes/{id}/scan-jobs` 下发探针扫描任务
- `POST /probes/{id}/data-assets/jobs` 下发探针数据资产采集任务
- `POST /probes/{id}/data-assets` 探针回传数据资产清单（探针鉴权）
- `GET /data/assets` 数据资产列表（支持 `probe_id` 筛选）
- `GET /assets` 资产列表
- `POST /files/upload` 上传文件
- `GET /files/{id}` 文件详情
- `POST /pcaps/upload` 上传 PCAP
- `POST /pcaps/{id}/analyze` 触发 PCAP 分析
- `GET /tasks` 任务列表
- `POST /algorithms/evaluate` 算法评估
- `POST /reports/generate` 生成报告
- `GET /reports/{id}/download` 下载报告
- `GET /dashboard/summary` 总览
- `GET /integrations` 集成组件列表
- `POST /integrations/{name}/analyze` 运行第三方适配器
- `POST /integrations/offline/import` 导入离线包
- `GET /incidents` 关联事件列表
- `GET /incidents/{id}` 关联事件详情
- `POST /incidents/correlate` 手工事件关联
- `GET /iocs` IOC 列表
