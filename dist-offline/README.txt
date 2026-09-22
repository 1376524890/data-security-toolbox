Data Security Toolbox 离线包

架构：本包内镜像为 arm64，目标机 uname -m 必须一致（aarch64 / x86_64 不可混用）。

一、联网的构建机（架构需与目标机相同）
1. 构建镜像：
   DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target api -t source-backend:latest .
   DOCKER_BUILDKIT=0 docker build -f backend/Dockerfile --target analysis-worker -t source-worker:latest -t source-deployment-worker:latest .
   DOCKER_BUILDKIT=0 docker build -t source-frontend:latest ./frontend
2. 已经生成镜像包 dist-offline/security-toolbox-images.tar（arm64）
3. 随包拷贝：dist-offline/、docker-compose.yml、.env（确认里面没有 DATA_ROOT）

二、目标内网机（无外网）
1. docker load -i security-toolbox-images.tar
2. 离线启动，禁止拉取与构建；缺镜像会直接报错而不是悄悄去拉：
   PULL_POLICY=never docker compose -p source -f docker-compose.yml up -d --no-build --pull never
3. docker compose -p source -f docker-compose.yml ps   # 等到 backend 显示 healthy
4. 导入离线规则 / IOC / CVE：
   docker compose -p source exec backend python -c "from app.core.database import SessionLocal; from app.integrations.offline_manager import import_offline_path; import pathlib; db=SessionLocal(); print(import_offline_path(db, pathlib.Path('/app/data/offline'), resource_type=None, name='bundle', version='1.0').to_dict()); db.close()"

三、镜像清单（6 个）
  - mher/flower:2.0.1
  - postgres:16.6-alpine
  - redis:7.4-alpine
  - source-backend:latest
  - source-frontend:latest
  - source-worker:latest

四、数据持久化
  postgres / redis / backend 数据都在宿主机目录 deploy-data/，不在匿名卷里；
  容器重建（--force-recreate）不会丢数据。db 里跑的是 alembic upgrade head，随连接启动。
