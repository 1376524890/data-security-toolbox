# 阶段一：顶层构建辅助
.PHONY: install probe server test dev

install:
	pip install -r server/requirements.txt
	pip install -r probe/requirements.txt

server:
	uvicorn server.app:app --reload --port 8000

probe:
	python -m probe.main --once

test:
	python -m pytest tests -q

lint:
	python -m py_compile probe/main.py probe/collectors/*.py probe/reporter.py probe/cache.py probe/config.py
	python -m py_compile server/app.py server/celery_app.py server/engine/base.py server/api/*.py server/models/*.py