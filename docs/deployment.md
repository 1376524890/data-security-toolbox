# 部署

```bash
cp .env.example .env
docker compose build
docker compose up -d
docker compose exec backend alembic upgrade head
docker compose exec backend python scripts/seed.py
```

访问：

- 管理台：http://localhost:8080
- OpenAPI：http://localhost:8000/docs
- Celery 监控：http://localhost:5555

