"""One definition of whether a probe is online, for every place that asks.

The console answered this question three different ways and they disagreed. The
probe list, the wall and ``/dashboard/overview`` re-derived the status from
``last_seen`` (a heartbeat older than 90 s is an offline probe); ``/dashboard/summary``
counted the stored ``Probe.status`` column instead, and ``services/cockpit_service``
read that column directly too. Nothing ever wrote the column back when heartbeats
stopped - only a *successful uninstall* moved it to ``offline`` - so a probe that
simply died stayed ``online`` in the column forever. The list said offline while
the summary said online, and an operator had no way to tell which number to trust.

So the rule lives here once, and the column is kept in step with it by a beat
(``mark_stale_offline``) rather than being a second opinion. A row still passes
through :func:`derive` on the way out, so a display is never wrong even if the
beat has not run yet.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.datetimes import aware
from app.models import Probe

#: A heartbeat older than this means the daemon is not talking to the platform.
#: The probe heartbeats every 30 s (``probe.py``), so this is three missed beats.
ONLINE_WINDOW_SECONDS = 90

ONLINE = "online"
DEGRADED = "degraded"
OFFLINE = "offline"

#: Values the derivation itself decides; a status outside this set (``auth_error``
#: is written by other subsystems) is left alone, because "we have not heard from
#: it" must not erase a reason we already know.
LIVENESS_STATUSES = (ONLINE, DEGRADED)


def derive(probe: Probe, now: datetime | None = None) -> str:
    """The status a probe row really has right now."""
    moment = now or datetime.now(UTC)
    last_seen = aware(probe.last_seen)
    if not isinstance(last_seen, datetime):
        # Registration alone is not proof the daemon is running: a probe must
        # heartbeat before it can be shown online.
        return OFFLINE
    if (moment - last_seen).total_seconds() > ONLINE_WINDOW_SECONDS:
        return OFFLINE
    return DEGRADED if probe.status == DEGRADED else ONLINE


def is_online(probe: Probe, now: datetime | None = None) -> bool:
    return derive(probe, now) == ONLINE


def mark_stale_offline(db: Session, now: datetime | None = None) -> int:
    """Write the column back in line with :func:`derive`.

    Only rows the derivation itself owns are touched: a probe that has been
    quiet past the window returns to ``offline``, exactly as the console would
    show it, so the stored column stops being a second, stale opinion.
    """
    moment = now or datetime.now(UTC)
    cutoff = moment - timedelta(seconds=ONLINE_WINDOW_SECONDS)
    rows = db.scalars(
        select(Probe).where(
            Probe.status.in_(LIVENESS_STATUSES),
            or_(Probe.last_seen.is_(None), Probe.last_seen < cutoff),
        )
    ).all()
    for probe in rows:
        probe.status = OFFLINE
    if rows:
        db.commit()
    return len(rows)
