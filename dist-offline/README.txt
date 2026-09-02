Data Security Toolbox offline bundle
1. docker compose build
2. docker compose --profile integrations build
3. docker save -o security-toolbox-images.tar postgres:16-alpine redis:7-alpine mher/flower:2.0 security-toolbox-backend security-toolbox-frontend
4. copy security-toolbox-images.tar, dist-offline, compose files, .env to target
5. docker compose --profile integrations up -d
6. docker compose exec backend python -c "from app.core.database import SessionLocal; from app.integrations.offline_manager import import_offline_path; import pathlib; db=SessionLocal(); print(import_offline_path(db, pathlib.Path('/app/data/offline'), resource_type=None, name='bundle', version='1.0').to_dict()); db.close()"
