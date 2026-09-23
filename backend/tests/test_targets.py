"""The wizard's target helpers: read-only, complete, and secret-preserving."""
from fastapi.testclient import TestClient

from app.main import app
from app.services import target_tree

#: A tree deep enough to prove the picker is not stopped at three levels.
TREE = {
    "/root": [("a", "dir", 0), ("x.txt", "file", 12)],
    "/root/a": [("b", "dir", 0)],
    "/root/a/b": [("c", "dir", 0)],
    "/root/a/b/c": [("d.txt", "file", 3)],
}


class _FakeSsh:
    def __init__(self, **kwargs) -> None:
        pass

    def connect(self) -> None:
        pass

    def close(self) -> None:
        pass

    def listdir(self, path):
        if path not in TREE:
            raise target_tree.SshError("path_error", "no such directory")
        return list(TREE[path])

#: Port 1 refuses immediately, so the test proves the failure path without a wait.
SPEC = {"protocol": "ssh", "host": "127.0.0.1", "port": 1, "username": "root",
        "auth_type": "password", "password": "s3cret-value"}


def test_unreachable_target_reports_a_category_not_the_secret() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/targets/test", json=SPEC)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False and body["protocol"] == "ssh"
    # The credential is used for this one call and must never come back.
    assert "s3cret-value" not in response.text


def test_browse_rejects_a_protocol_it_cannot_enumerate() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/targets/browse", json={**SPEC, "protocol": "ftp"})
    assert response.status_code == 400


def test_browse_returns_one_level_per_call_so_the_tree_can_go_any_depth(monkeypatch) -> None:
    """The lazy picker expands level by level; each call must hand it exactly the
    children of the expanded node, and depth must not be capped at 3."""
    monkeypatch.setattr(target_tree, "SshClient", _FakeSsh)
    listing = target_tree.browse_ssh({"host": "10.0.0.5"}, roots=["/root"], max_depth=1)
    assert [row["path"] for row in listing["rows"]] == ["/root/a", "/root/x.txt"]
    assert {row["depth"] for row in listing["rows"]} == {1}
    assert listing["truncated"] is False

    whole = target_tree.browse_ssh({"host": "10.0.0.5"}, roots=["/root"], max_depth=0)
    assert {row["path"] for row in whole["rows"]} == {
        "/root/a", "/root/x.txt", "/root/a/b", "/root/a/b/c", "/root/a/b/c/d.txt"}
    assert whole["truncated"] is False


def test_browse_only_truncates_when_the_caller_asks_for_a_cap(monkeypatch) -> None:
    monkeypatch.setattr(target_tree, "SshClient", _FakeSsh)
    capped = target_tree.browse_ssh({"host": "10.0.0.5"}, roots=["/root"], max_depth=0,
                                    max_entries=2)
    assert capped["truncated"] is True and capped["reason"] == "entry_budget"
    assert len(capped["rows"]) == 2


def test_browse_depth_defaults_to_no_cap() -> None:
    """Omitting max_depth must not silently mean "three levels"."""
    from app.api.targets import TargetSpec

    spec = TargetSpec(host="10.0.0.5")
    assert spec.max_depth == 0 and spec.max_entries == 0


def test_test_rejects_an_unknown_auth_type() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/targets/test", json={**SPEC, "auth_type": "kerberos"})
    assert response.status_code == 400
