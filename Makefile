.PHONY: build up down logs test lint format migrate shell frontend-build

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

migrate:
	docker compose run --rm backend alembic upgrade head

shell:
	docker compose exec backend /bin/bash

test:
	docker compose run --rm backend pytest -q

lint:
	docker compose run --rm backend ruff check app tests

format:
	docker compose run --rm backend ruff format app tests

frontend-build:
	docker compose run --rm frontend npm run build

