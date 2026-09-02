# 离线部署

在线环境准备离线包：

```bash
python scripts/offline_bundle.py
```

目标内网服务器执行：

```bash
docker load < security-toolbox-images.tar
docker compose up -d
docker compose exec backend alembic upgrade head
docker compose exec backend python scripts/seed.py
```

离线包包含：Docker 镜像、pip wheelhouse、npm 离线缓存、部署文档。

