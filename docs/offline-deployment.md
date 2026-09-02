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

如需启动 Zeek、Suricata、MISP、Wazuh、osquery、OpenSCAP 集成组件：

```bash
docker compose -f docker-compose.yml -f docker-compose.integrations.yml --profile integrations up -d
```

导入离线规则、IOC、CVE、模型包：

```bash
docker compose exec backend python -c \
  "from app.core.database import SessionLocal; from app.integrations.offline_manager import import_offline_path; import pathlib; db=SessionLocal(); print(import_offline_path(db, pathlib.Path('/app/data/offline'), resource_type=None, name='bundle', version='1.0').to_dict()); db.close()"
```

离线包目录 `dist-offline/data` 包含：

- `rules/`：Suricata ET Open 示例规则
- `iocs/`：MISP 离线 IOC
- `cves/`：CVE 离线清单
- `models/`：Presidio 中文 PII 自定义模型配置

离线包包含：Docker 镜像、pip wheelhouse、npm 离线缓存、部署文档和集成组件离线数据。
