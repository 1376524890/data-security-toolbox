"""End-to-end Probe push-deployment test against a real Linux target.

Starts the backend in-process on 0.0.0.0:8000, creates a deployment over the
API, then polls the deployment state until ONLINE or FAILED. The Probe on the
target registers and heartbeats back to ``DEPLOYMENT_BACKEND_URL``.

Usage (from source/):
    python scripts/deploy_e2e_test.py
"""

from __future__ import annotations

import os
import sys
import time
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("DATABASE_URL", "sqlite:///./data/deploy_test.db")
os.environ.setdefault("STORAGE_DIR", "./data/deploy_test_storage")
os.environ.setdefault("REPORT_DIR", "./data/deploy_test_reports")
os.environ.setdefault("DEPLOYMENT_SECRET_KEY", "deploy-e2e-test-secret-key-32-chars!!")
os.environ.setdefault("DEPLOYMENT_PACKAGE_DIR", str(ROOT / "probe_packages"))
os.environ.setdefault("DEPLOYMENT_BACKEND_URL", "http://192.168.191.1:8000")
os.environ.setdefault("DEPLOYMENT_VERIFY_HOST_KEY", "false")
os.environ.setdefault("DEPLOYMENT_ALLOW_PASSWORD", "true")
os.environ.setdefault("PROBE_AGENT_VERSION", "3.2.0")

import httpx  # noqa: E402
import uvicorn  # noqa: E402
from app.main import app  # noqa: E402


def main() -> int:
    db = Path(ROOT / "backend" / "data" / "deploy_test.db")
    db.unlink(missing_ok=True)
    server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 30
    while not server.started and time.time() < deadline:
        time.sleep(0.2)
    if not server.started:
        print("backend failed to start", file=sys.stderr)
        return 1
    base = "http://127.0.0.1:8000/api/v1"
    try:
        health = httpx.get(f"{base}/health", timeout=10).json()
        print("health:", health["status"])
    except Exception as exc:  # noqa: BLE001
        print("health check failed:", exc, file=sys.stderr)
        server.should_exit = True
        return 1

    payload = {
        "name": "kali-e2e",
        "host": os.environ.get("DEPLOY_TARGET_HOST", "192.168.191.128"),
        "port": int(os.environ.get("DEPLOY_TARGET_PORT", "22")),
        "username": os.environ.get("DEPLOY_TARGET_USER", "root"),
        "auth_type": "password",
        "password": os.environ.get("DEPLOY_TARGET_PASSWORD", "0210"),
        "profile": os.environ.get("DEPLOY_TARGET_PROFILE", "standard"),
        "idempotency_key": f"e2e-{int(time.time())}",
    }
    resp = httpx.post(f"{base}/probe-deployments", json=payload, timeout=30)
    print("create:", resp.status_code)
    if resp.status_code != 202:
        print(resp.text, file=sys.stderr)
        server.should_exit = True
        return 1
    dep = resp.json()
    dep_id = dep["id"]
    print("deployment id:", dep_id)

    for attempt in range(120):
        detail = httpx.get(f"{base}/probe-deployments/{dep_id}", timeout=10).json()
        print(
            f"[{attempt:02d}] status={detail['status']} stage={detail['current_stage']} "
            f"progress={detail['progress']} probe={detail.get('probe_id')} "
            f"err={detail.get('error_code')} {detail.get('error_message','')[:80]}"
        )
        if detail["status"] in {"ONLINE", "FAILED"}:
            for event in detail.get("events", []):
                print("  event:", event["stage"], "-", event["message"])
            if detail["status"] == "ONLINE":
                print("RESULT: ONLINE")
                return 0
            print("RESULT: FAILED", file=sys.stderr)
            return 1
        time.sleep(5)
    print("timeout waiting for deployment", file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        pass
