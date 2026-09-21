"""Functional checks for the policy-group CRUD surface."""
from fastapi.testclient import TestClient

from app.main import app


def _draft(name: str = "网上银行合规策略") -> dict:
    return {"name": name, "description": "覆盖网络与文件的敏感检测", "scope": ["network", "file"],
            "rule_ids": ["ID_CARD", "BANK_CARD"], "categories": ["ID_CARD"], "keywords": ["内部机密"],
            "min_confidence": 0.7, "min_matches": 2}


def test_policy_group_round_trip() -> None:
    with TestClient(app) as client:
        created = client.post("/api/v1/policy-groups", json=_draft())
        assert created.status_code == 200, created.text
        group = created.json()
        assert group["version"] == 1 and group["scope"] == ["network", "file"]

        listed = client.get("/api/v1/policy-groups", params={"page": 1, "page_size": 10}).json()
        assert any(item["id"] == group["id"] for item in listed["items"])

        patched = client.patch(f"/api/v1/policy-groups/{group['id']}", json={"min_matches": 5})
        assert patched.status_code == 200
        assert patched.json()["min_matches"] == 5 and patched.json()["version"] == 2

        deleted = client.delete(f"/api/v1/policy-groups/{group['id']}")
        assert deleted.status_code == 200
        assert client.get(f"/api/v1/policy-groups/{group['id']}").status_code == 404


def test_policy_group_rejects_duplicate_and_bad_scope() -> None:
    with TestClient(app) as client:
        first = client.post("/api/v1/policy-groups", json=_draft("唯一名称-1"))
        assert first.status_code == 200
        try:
            duplicate = client.post("/api/v1/policy-groups", json=_draft("唯一名称-1"))
            assert duplicate.status_code == 409
            bad = client.post("/api/v1/policy-groups", json={**_draft("唯一名称-2"),
                                                             "scope": ["telepathy"]})
            assert bad.status_code == 400
        finally:
            client.delete(f"/api/v1/policy-groups/{first.json()['id']}")


def test_policy_group_delete_blocked_while_an_open_task_references_it() -> None:
    """A group a pending task snapshotted must not vanish under it."""
    from app.core.database import SessionLocal
    from app.models import Task

    with TestClient(app) as client:
        group = client.post("/api/v1/policy-groups", json=_draft("被引用策略")).json()
        with SessionLocal() as db:
            task = Task(kind="data_asset_scan", status="Pending",
                        payload={"policy_group_ids": [group["id"]]})
            db.add(task)
            db.commit()
            task_id = task.id
        try:
            blocked = client.delete(f"/api/v1/policy-groups/{group['id']}")
            assert blocked.status_code == 409
        finally:
            with SessionLocal() as db:
                row = db.get(Task, task_id)
                if row:
                    db.delete(row)
                    db.commit()
            client.delete(f"/api/v1/policy-groups/{group['id']}")
