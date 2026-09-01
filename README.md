# 数据安全检测工具箱 - 开发仓库

探针采集 + FastAPI 后端 + Vue 前端 + 五大检测模块全功能保留。

## 目录结构

```
data-security-toolbox/
  probe/          # 探针 Agent（目标机数据采集）
  server/         # 后端 API + 检测引擎
  web/            # 前端（Vue 3 + Element Plus）
  shared/         # 探针与后端共用的数据模型与常量
  deploy/         # 部署（阶段六）
```

## 快速启动

```bash
# 1. 后端依赖 + 启动（需本地 PostgreSQL + Redis，见 deploy/docker-compose.yml）
pip install -r server/requirements.txt
uvicorn server.app:app --reload --port 8000

# 2. 前端依赖 + 启动
cd web && npm install && npm run dev

# 3. 探针（一次性：注册 + 采集 + 上报）
pip install -r probe/requirements.txt
python -m probe.main --once
```

## 接口速览

| 模块 | 路径 |
|------|------|
| 探针注册 | POST /api/probe/register |
| 探针心跳 | POST /api/probe/heartbeat |
| 任务下发 | POST /api/tasks |
| 结果上报 | POST /api/probe/{id}/upload |
| 结果查询 | GET /api/results/{type} |
| 报告汇总 | GET /api/results/summary |
| 资产敏感数据识别 | POST /api/asset/analyze |
| 正则生成工具 | POST /api/tools/regex-gen |
| 协议分析 | POST /api/protocol/analyze |
| 流量分析 | POST /api/traffic/analyze |
| 元数据分析 | POST /api/metadata/analyze |
| 密码算法评估 | POST /api/algo/analyze |
| 模块能力清单 | GET /api/modules |
| 仪表盘 | GET /api/dashboard/stats |

> 五大检测模块已全部实现（资产识别 / 元数据分析 / 算法评估 / 协议分析 / 流量分析）。
> 阶段进度：全部完成 ✅。

## 运行测试

```bash
# 引擎级单元测试（无需外部服务）
python -m pytest tests/test_traffic.py tests/test_engines.py

# API 冒烟测试（需后端已启动，否则自动跳过）
python -m pytest tests/test_smoke.py
```

## Docker 部署

```bash
cd deploy
docker-compose up -d --build
# 前端:  http://localhost
# 后端:  http://localhost/api（经 Nginx 反代）
```

服务组成：`postgres`(存储)、`redis`(异步/缓存)、`backend`(FastAPI)、`worker`(Celery)、`frontend`(Nginx+Vue 静态)。

生产环境需修改 `docker-compose.yml` 中的默认口令与数据集市，并将 `ports` 暴露范围收紧为内网或 TLS 前置。