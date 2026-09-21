"""A risky file is proposed, not imposed: candidate → accepted → task-scoped rule."""
from app.core.database import SessionLocal
from app.models import PolicyGroup
from app.services import fingerprint_candidates as candidates

SHA = "a" * 64
OTHER = "b" * 64


def _clear(db) -> None:
    for group in db.query(PolicyGroup).all():
        db.delete(group)
    db.query(__import__("app.models", fromlist=["SystemSetting"]).SystemSetting).filter_by(
        key=candidates.CANDIDATE_KEY).delete()
    db.commit()


def test_only_high_risk_with_a_full_sha256_is_proposed() -> None:
    with SessionLocal() as db:
        _clear(db)
        assert candidates.record(db, sha256="not-a-hash", path="/a", name="a",
                                  source_name="s", level="L4", severity="Critical",
                                  task_id=1) is False
        assert candidates.record(db, sha256=SHA, path="/a", name="a", source_name="s",
                                 level="L2", severity="Medium", task_id=1) is False
        assert candidates.record(db, sha256=SHA, path="/a", name="a", source_name="s",
                                 level="L4", severity="Critical", task_id=1) is True
        # The same content is never proposed twice.
        assert candidates.record(db, sha256=SHA, path="/a", name="a", source_name="s",
                                 level="L4", severity="Critical", task_id=1) is False
        db.commit()
        assert [item["sha256"] for item in candidates.list_candidates(db)] == [SHA]


def test_accepting_puts_the_hash_in_a_task_scoped_group_only() -> None:
    with SessionLocal() as db:
        _clear(db)
        candidates.record(db, sha256=SHA, path="/srv/keys.pem", name="keys.pem",
                          source_name="src", level="L4", severity="Critical", task_id=7)
        candidates.record(db, sha256=OTHER, path="/srv/id_rsa", name="id_rsa",
                          source_name="src", level="L4", severity="Critical", task_id=7)
        db.commit()

        accepted = candidates.accept(db, SHA)
        assert accepted["group_name"] == "任务 #7 指纹"
        # The second accept lands in the same group rather than making another one.
        assert candidates.accept(db, OTHER)["group_id"] == accepted["group_id"]

        group = db.get(PolicyGroup, accepted["group_id"])
        assert group.fingerprints == [SHA, OTHER]
        assert db.query(PolicyGroup).count() == 1          # no default policy touched
        statuses = {item["sha256"]: item["status"] for item in candidates.list_candidates(db)}
        assert statuses == {SHA: "accepted", OTHER: "accepted"}


def test_ignoring_keeps_it_out_of_every_group() -> None:
    with SessionLocal() as db:
        _clear(db)
        candidates.record(db, sha256=SHA, path="/a", name="a", source_name="s",
                          level="L4", severity="Critical", task_id=3)
        db.commit()
        candidates.ignore(db, SHA)
        assert db.query(PolicyGroup).count() == 0
        assert candidates.list_candidates(db)[0]["status"] == "ignored"
