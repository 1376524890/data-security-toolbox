r"""Ranking the rules that raise the most, and dry-running one over its own history.

After a false-positive sweep an operator asks two questions: which rule produced
all of that, and what would this rule do if I switched it on? Both are answered
from rows that already exist, and neither writes anything.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import (
    Alert,
    AlertHit,
    AssetInstance,
    Base,
    Detection,
    DetectionEvidence,
    DetectionFinding,
)
from app.services import rule_noise


def _session(tmp_path):
    """A database of this test's own: the report reads every row in the table."""
    engine = create_engine(f"sqlite:///{tmp_path / 'noise.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _detection(db, path: str, category: str, rule_id: str, *, values=(), kind="regex",
               confidence=0.9):
    instance = AssetInstance(object_id=1, owner_key="probe:1", source_kind="file", path=path,
                             name=path.rsplit("/", 1)[-1], size=10, status="ACTIVE")
    db.add(instance)
    db.flush()
    detection = Detection(object_id=1, instance_id=instance.id, source_kind="file",
                         category=category, sensitivity_level="L3", severity="High",
                         confidence=confidence)
    db.add(detection)
    db.flush()
    db.add(DetectionEvidence(detection_id=detection.id, rule_id=rule_id, evidence_key=path,
                             evidence_type=kind, hit_count=len(values) or 1, confidence=confidence,
                             extra={"matches": [{"value": value} for value in values]}))
    db.flush()
    return detection


def _alerted_finding(db, rule_id: str) -> DetectionFinding:
    finding = DetectionFinding(engine="network_traffic_engine", rule_id=rule_id,
                               target_type="traffic", target_id="1.2.3.4", severity="High")
    db.add(finding)
    db.flush()
    alert = Alert(fingerprint=rule_id, severity="High", title=rule_id)
    db.add(alert)
    db.flush()
    db.add(AlertHit(alert_id=alert.id, finding_id=finding.id, source="pipeline"))
    db.flush()
    return finding


def test_the_report_ranks_a_rule_the_platform_would_not_raise(tmp_path) -> None:
    with _session(tmp_path) as db:
        # A digit-only pack rule: the platform reads it below the confirm
        # threshold, no matter what its own pack scored it.
        for index in range(3):
            _detection(db, f"/srv/noise/{index}.sh", "se_organisationsnummer",
                       "rule-that-is-not-in-the-store")
        _detection(db, "/srv/data/real.csv", "email", "SD_EMAIL_001", values=("a@b.com",))
        _alerted_finding(db, "NETWORK_PORT_SCAN")

        report = rule_noise.noise_report(db)
        items = {item["rule_id"]: item for item in report["items"]}

        unknown = items["rule-that-is-not-in-the-store"]
        assert unknown["detections"] == 3 and unknown["evidence_rows"] == 3
        # Evidence that cannot name a rule this platform holds is evidence it
        # cannot vouch for, so every row of it is unconfirmable.
        assert unknown["unconfirmable_rows"] == 3
        assert unknown["noise_ratio"] == 1.0
        # The traffic and YARA rules alert without a data rule of their own, so
        # "not in the sensitivity store" is reported as unknown, not as "cannot
        # alert".
        assert unknown["alertable"] is None and unknown["known_rule"] is False
        assert unknown["platform_confidence"] is None

        confirmed = items["SD_EMAIL_001"]
        assert confirmed["platform_confidence"] == 0.85
        assert confirmed["alertable"] is True and confirmed["known_rule"] is True
        assert confirmed["unconfirmable_rows"] == 0

        assert report["confirm_threshold"] == 0.6
        # An alert outranks a pile of detections: it is what a human was shown.
        assert report["items"][0]["rule_id"] == "NETWORK_PORT_SCAN"
        assert items["NETWORK_PORT_SCAN"]["alerts"] == 1


def test_a_field_hint_is_never_scored_like_a_value(tmp_path) -> None:
    with _session(tmp_path) as db:
        _detection(db, "/srv/data/headers.csv", "email", "SD_EMAIL_001",
                   values=("header",), kind="field_name")

        item = rule_noise.noise_report(db)["items"][0]

        # The rule is confident, but a header name is not a value: this row can
        # never confirm, and the report says so.
        assert item["platform_confidence"] == 0.85
        assert item["unconfirmable_rows"] == 1
        assert item["noise_ratio"] == 1.0


def test_replay_keeps_what_the_current_rule_still_matches(tmp_path) -> None:
    with _session(tmp_path) as db:
        # The connection-string host the email rule used to accept, next to a
        # real address: the validator is what tells them apart.
        _detection(db, "/srv/data/mixed.csv", "email", "SD_EMAIL_001",
                   values=("security@172.18.0.2", "someone@example.com"))

        result = rule_noise.replay(db, "SD_EMAIL_001")

        assert result["tested"] == 2
        assert result["matched"] == 1
        assert result["alertable"] is True
        assert "只读" in result["note"]


def test_replay_of_a_rule_the_platform_does_not_hold_is_not_guessed(tmp_path) -> None:
    with _session(tmp_path) as db:
        assert rule_noise.replay(db, "vendor-rule-that-is-gone") is None


def test_replay_of_a_rule_without_a_pattern_says_so(tmp_path) -> None:
    with _session(tmp_path) as db:
        result = rule_noise.replay(db, "SD_NAME_001")

        assert result["tested"] == 0 and result["matched"] == 0
        assert result["alertable"] is False
        assert "正则" in result["note"]


def test_the_noise_report_and_replay_are_reachable_and_read_only(tmp_path, monkeypatch) -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.pool import StaticPool

    from app.api.libraries import router
    from app.core.config import settings
    from app.core.database import get_db

    monkeypatch.setattr(settings, "integration_dir", tmp_path / "integrations")
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        _detection(db, "/srv/data/a.csv", "email", "SD_EMAIL_001", values=("a@b.com",))
        db.commit()
        api = FastAPI()
        api.include_router(router)
        api.dependency_overrides[get_db] = lambda: db
        with TestClient(api) as client:
            report = client.get("/api/v1/dlp/rules/noise")
            assert report.status_code == 200
            body = report.json()
            assert body["total"] == 1 and body["items"][0]["rule_id"] == "SD_EMAIL_001"
            assert body["confirm_threshold"] == 0.6

            replay = client.post("/api/v1/dlp/rules/SD_EMAIL_001/replay")
            assert replay.status_code == 200
            assert replay.json()["tested"] == 1 and replay.json()["matched"] == 1

            # A rule this platform does not hold is a 404, not an invented report.
            assert client.post("/api/v1/dlp/rules/gone/replay").status_code == 404
        # Nothing was written: the dry run left the row exactly as it was.
        assert db.query(DetectionEvidence).count() == 1
    engine.dispose()
