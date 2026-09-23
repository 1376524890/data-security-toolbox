"""The free-space floor and the segment eviction it drives.

The platform is the one producer that can fill its own disk: a probe in
monitoring mode uploads segments faster than they are analysed, and the only
bound used to be an age sweep plus a ``PCAP_STORAGE_MAX_GB`` the console merely
*displayed*. A full data partition takes Postgres (and the console) down with it,
so these tests pin the two decisions that prevent it: refuse ingest *before* the
disk is full, and delete segment *files* - never their rows - oldest first.
"""
from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Alert, Base, DetectionFinding, PcapRecord
from app.services import pcap_storage, storage_guard

GIB = 1024 ** 3


def _isolated_session(tmp_path):
    """A database of this test's own.

    Eviction sweeps every segment in the table, so running it against the shared
    test database would make the counts depend on what other tests left behind.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'storage-guard.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _segment(db, tmp_path, index, size=2048):
    path = tmp_path / f"segment-{index}.pcap"
    path.write_bytes(b"x" * size)
    record = PcapRecord(filename=path.name, storage_path=str(path), size=size,
                        sha256=f"sha{index}", probe_id=None, segment_id=f"segment-{index}")
    db.add(record)
    db.flush()
    return record, path


def _usage(free_bytes, total_bytes=1000 * GIB, used=0):
    return {"path": "/data", "total_bytes": total_bytes, "used_bytes": used,
            "free_bytes": free_bytes, "used_percent": 0.0, "free_percent": 0.0}


def test_floor_is_the_larger_of_the_absolute_and_percentage_values(monkeypatch) -> None:
    monkeypatch.setattr(storage_guard.settings, "pcap_storage_min_free_gb", 5)
    monkeypatch.setattr(storage_guard.settings, "pcap_storage_min_free_percent", 10.0)
    # 10% of a small disk is under 5 GiB, so the absolute number protects it.
    assert storage_guard.floor_bytes(10 * GIB) == 5 * GIB
    # On a large disk the percentage is the larger of the two, so it wins.
    assert storage_guard.floor_bytes(1000 * GIB) == 100 * GIB


def test_only_critical_stops_ingest(monkeypatch) -> None:
    monkeypatch.setattr(storage_guard.settings, "pcap_storage_min_free_gb", 10)
    monkeypatch.setattr(storage_guard.settings, "pcap_storage_min_free_percent", 0.0)
    monkeypatch.setattr(storage_guard.settings, "pcap_storage_warning_free_multiplier", 2.0)

    def verdict(available_gib):
        return storage_guard.pressure(_usage(available_gib * GIB))

    assert verdict(30)["state"] == "ok"
    assert verdict(15)["state"] == "warning"
    # "below the floor" is strict: sitting exactly on it is still allowed.
    assert verdict(10)["state"] == "warning"
    assert verdict(9)["state"] == "critical"
    # A warning is a colour, not a refusal.
    assert storage_guard.ingest_blocked(verdict(15)) is None
    assert storage_guard.ingest_blocked(verdict(10)) is None
    reason = storage_guard.ingest_blocked(verdict(9))
    assert reason and "暂停接收抓包" in reason


def test_eviction_frees_unheld_segments_and_keeps_the_row(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pcap_storage, "stored_bytes", lambda: 0)
    with _isolated_session(tmp_path) as db:
        plain, plain_path = _segment(db, tmp_path, 1)
        held, held_path = _segment(db, tmp_path, 2)
        finding = DetectionFinding(target_type="pcap", target_id=str(held.id),
                                   engine="traffic", rule_id="NET_SCAN_001",
                                   severity="High", evidence={})
        db.add(finding)
        db.flush()
        db.add(Alert(fingerprint=f"fp-{finding.id}", finding_id=finding.id,
                     severity="High", title="held /1", status="new"))
        db.flush()
        assert pcap_storage.holds_open_case(db, held)

        result = pcap_storage.evict_oldest(db, include_held=False)

        assert not plain_path.exists()
        assert held_path.exists()
        # The record survives the file: a finding still has to say where its
        # evidence came from.
        assert plain.retention_status == "retained_analysis"
        assert result["skipped_held"] >= 1


def test_the_floor_overrides_the_hold_on_open_forensic_payload(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pcap_storage, "stored_bytes", lambda: 0)
    with _isolated_session(tmp_path) as db:
        held, held_path = _segment(db, tmp_path, 1)
        finding = DetectionFinding(target_type="pcap", target_id=str(held.id),
                                   engine="traffic", rule_id="NET_SCAN_001",
                                   severity="High", evidence={})
        db.add(finding)
        db.flush()
        db.add(Alert(fingerprint=f"fp-{finding.id}", finding_id=finding.id,
                     severity="High", title="held /1", status="new"))
        db.flush()
        assert pcap_storage.holds_open_case(db, held)

        # Keeping forensic payload is the default, but filling the disk destroys
        # every payload at once, so the hold is a priority rather than a veto.
        pcap_storage.evict_oldest(db, include_held=True)
        assert not held_path.exists()
        assert held.retention_status == "retained_analysis"


def test_age_sweep_extends_held_segments_instead_of_deleting_them(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(pcap_storage, "stored_bytes", lambda: 0)
    with _isolated_session(tmp_path) as db:
        plain, plain_path = _segment(db, tmp_path, 1)
        held, held_path = _segment(db, tmp_path, 2)
        finding = DetectionFinding(target_type="pcap", target_id=str(held.id),
                                   engine="traffic", rule_id="NET_SCAN_001",
                                   severity="High", evidence={})
        db.add(finding)
        db.flush()
        db.add(Alert(fingerprint=f"fp-{finding.id}", finding_id=finding.id,
                     severity="High", title="held /1", status="new"))
        db.flush()

        result = pcap_storage.cleanup_expired(db, datetime.now(UTC))

        assert not plain_path.exists()
        assert held_path.exists()
        assert held.retention_status == "extended"
        assert result["extended"] == 1 and result["removed"] >= 1


def test_space_sweep_does_nothing_while_the_partition_is_healthy(tmp_path, monkeypatch) -> None:
    with _isolated_session(tmp_path) as db:
        _record, path = _segment(db, tmp_path, 1)
        monkeypatch.setattr(pcap_storage.storage_guard, "pressure", lambda usage=None: {
            **_usage(300 * GIB), "floor_bytes": 5 * GIB, "warning_bytes": 10 * GIB,
            "state": "ok", "limit_bytes": 100 * GIB,
        })
        monkeypatch.setattr(pcap_storage, "stored_bytes", lambda: 1 * GIB)

        result = pcap_storage.enforce_cap(db)

        assert result["removed"] == 0
        assert path.exists()
