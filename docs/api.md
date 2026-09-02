# API 概览

FastAPI 启动后可在 `http://localhost:8000/docs` 查看 OpenAPI 文档。

主要接口前缀：`/api/v1`

- `POST /probes/register` 注册探针
- `POST /probes/{id}/heartbeat` 探针心跳
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
