Data Security Toolbox offline bundle
1. docker compose build
2. docker compose --profile integrations build
3. docker save -o security-toolbox-images.tar postgres:16-alpine redis:7-alpine mher/flower:2.0 security-toolbox-backend security-toolbox-frontend
4. copy security-toolbox-images.tar, dist-offline, compose files, .env to target
5. docker compose --profile integrations up -d
6. docker compose exec backend python -c "from app.integrations.offline import import_offline_bundle; print(import_offline_bundle('/app/data/offline'))"
