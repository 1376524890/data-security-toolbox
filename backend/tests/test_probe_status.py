"""One answer to "is this probe online?", for every place that asks it.

The console used to count probes two ways: the list and the wall re-derived the
status from ``last_seen``, while ``/dashboard/summary`` and the cockpit read the
stored ``Probe.status`` column. Nothing wrote that column back when heartbeats
stopped, so a dead probe stayed ``online`` in one number and ``offline`` in the
other, and the operator had no way to tell which one to believe.
"""
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.probe_presenter import serialize_probe
from app.models import Base, Probe
from app.services import probe_status


def _session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'probes.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_a_fresh_heartbeat_is_online() -> None:
    probe = Probe(name='fresh', status='online', last_seen=datetime.now(UTC))
    assert probe_status.derive(probe) == 'online'


def test_registration_alone_is_not_online() -> None:
    """A row says the probe asked to exist, not that the daemon is running."""
    probe = Probe(name='never-heartbeat', status='online', last_seen=None)
    assert probe_status.derive(probe) == 'offline'


def test_a_heartbeat_past_the_window_is_offline() -> None:
    stale = datetime.now(UTC) - timedelta(seconds=probe_status.ONLINE_WINDOW_SECONDS + 1)
    probe = Probe(name='quiet', status='online', last_seen=stale)
    assert probe_status.derive(probe) == 'offline'
    assert probe_status.is_online(probe) is False


def test_degraded_survives_while_it_is_still_talking() -> None:
    probe = Probe(name='degraded', status='degraded', last_seen=datetime.now(UTC))
    assert probe_status.derive(probe) == 'degraded'
    assert probe_status.is_online(probe) is False


def test_the_sweep_writes_back_only_what_the_derivation_owns(tmp_path) -> None:
    with _session(tmp_path) as db:
        stale = datetime.now(UTC) - timedelta(seconds=probe_status.ONLINE_WINDOW_SECONDS + 5)
        db.add_all([
            Probe(name='still-talking', status='online', last_seen=datetime.now(UTC)),
            Probe(name='went-quiet', status='online', last_seen=stale),
            Probe(name='was-degraded', status='degraded', last_seen=stale),
            Probe(name='auth-trouble', status='auth_error', last_seen=stale),
            Probe(name='already-offline', status='offline', last_seen=stale),
        ])
        db.flush()

        assert probe_status.mark_stale_offline(db) == 2
        assert db.query(Probe).filter(Probe.name == 'still-talking').one().status == 'online'
        assert db.query(Probe).filter(Probe.name == 'went-quiet').one().status == 'offline'
        assert db.query(Probe).filter(Probe.name == 'was-degraded').one().status == 'offline'
        # "We have not heard from it" must not erase a reason we already know.
        assert db.query(Probe).filter(Probe.name == 'auth-trouble').one().status == 'auth_error'


def test_the_row_the_console_shows_carries_the_same_verdict(tmp_path) -> None:
    with _session(tmp_path) as db:
        stale = datetime.now(UTC) - timedelta(seconds=probe_status.ONLINE_WINDOW_SECONDS + 5)
        db.add(Probe(name='shown', status='online', last_seen=stale))
        db.flush()
        probe = db.query(Probe).filter(Probe.name == 'shown').one()
        assert serialize_probe(probe)['status'] == 'offline'
