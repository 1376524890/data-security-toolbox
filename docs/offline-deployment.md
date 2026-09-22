# 离线部署

支持在无外网的内网机上部署；**镜像与目标机架构必须一致**，`aarch64` 与 `x86_64` 的包不能混用。

## 一、联网的构建机（架构需与目标机相同）

```bash
python scripts/offline_bundle.py --save
```

脚本会：读 `docker-compose.yml` 列出全部镜像 → 逐个核对镜像架构与目标机一致（不一致直接报错）→
拷贝 `backend/app/integrations/offline_data/` 到 `dist-offline/data` → 生成
`dist-offline/security-toolbox-images.tar` 与 `dist-offline/README.txt`。

不带 `--save` 时只生成清单与文档，并打印完整的 `docker save` 命令。
`--skip-arch-check` 仅用于明知架构不同仍要打包的场景。

构建镜像本身（约 3–5 分钟/个，必须用 legacy builder）：

```bash
DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target api -t source-backend:latest .
DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target analysis-worker -t source-worker:latest -t source-deployment-worker:latest .
DOCKER_BUILDKIT=0 docker build -t source-frontend:latest ./frontend
```

随包拷贝 `dist-offline/`、`docker-compose.yml`、`.env` 三样即可。

## 二、目标内网机

```bash
docker load -i dist-offline/security-toolbox-images.tar
PULL_POLICY=never docker compose -p source -f docker-compose.yml up -d --no-build --pull never
docker compose -p source -f docker-compose.yml ps      # 等 backend 变成 healthy
```

`--no-build` 与 `--pull never` 一起保证全程不联网：镜像齐全就正常启动，缺哪个镜像会**直接报错**
而不是悄悄去拉取（在离线环境里挂起的拉取会被误判成“卡住”）。
`PULL_POLICY=never` 是同一个约束写进 compose 文件的形式，两者同时加上更稳。

如需启动 Zeek、Suricata、MISP、Wazuh、osquery、OpenSCAP 集成组件：

```bash
docker compose -f docker-compose.yml -f docker-compose.integrations.yml --profile integrations up -d
```

导入离线规则、IOC、CVE、模型包：

```bash
docker compose -p source exec backend python -c \
  "from app.core.database import SessionLocal; from app.integrations.offline_manager import import_offline_path; import pathlib; db=SessionLocal(); print(import_offline_path(db, pathlib.Path('/app/data/offline'), resource_type=None, name='bundle', version='1.0').to_dict()); db.close()"
```

离线包目录 `dist-offline/data` 包含：

- `rules/`：Suricata ET Open 示例规则
- `iocs/`：MISP 离线 IOC
- `cves/`：CVE 离线清单
- `models/`：Presidio 中文 PII 自定义模型配置

## 三、数据持久化

`postgres` / `redis` / `backend` 的数据目录都映射到宿主机 `deploy-data/`，compose 里没有匿名卷，
因此 `--force-recreate` 重建容器不会丢数据。注意两点：

- `.env` 里**不要**改 `DATA_ROOT`：改了会让容器去读另一个空目录，看起来像“数据丢了”。
- 数据库结构随连接启动时执行 `alembic upgrade head`，不需要手工迁移。
