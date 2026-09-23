"""Eviction of capture segments, and the retention rules that bound it.

A capture segment is the only artefact the platform stores in bulk, so it is the
only one that can be dropped to make room. Two callers share this module:

- the age sweep (``cleanup_pcap_retention``), which removes segments older than
  ``PCAP_RETENTION_DAYS``;
- the space sweep (``enforce_pcap_storage_cap``), which removes the *oldest*
  segments when the data partition approaches its cap or its free-space floor.

Both keep the row and delete only the file, so a deleted capture stays
attributable: findings, alerts and incidents keep pointing at the segment they
were derived from, and the console can say the payload is gone instead of
silently losing the link.

The one rule that used to be absolute - never delete a segment that still holds
an open alert or incident - is now a *priority*, not a veto. Keeping forensic
payload is the right default, but filling the disk takes the database down and
destroys every payload at once; when the free-space floor is crossed, the oldest
held segment goes too, and its row records why.

Space is always measured on the storage directory itself, never on a running
total kept by the caller: an estimate that drifts would either stop early (the
disk fills anyway) or never stop (every segment is deleted).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Alert, DetectionFinding, Incident, PcapRecord
from app.services import storage_guard

#: Retention states. ``active`` = still within its retention window;
#: ``extended`` = held past the window because an alert/incident still needs it;
#: ``retained_analysis`` = the file is gone but the row and its findings remain.
STATUS_ACTIVE = "active"
STATUS_EXTENDED = "extended"
STATUS_RETAINED = "retained_analysis"


def stored_bytes() -> int:
    """Bytes the platform's data directory currently holds."""
    return storage_guard.dir_bytes(settings.storage_dir)


def open_case_pcap_ids(db: Session) -> set[str]:
    """Segments IDs an open alert or incident still points at.

    Loaded once for a whole sweep rather than per record: asking the question
    record-by-record meant one full scan of the incident table each time, and on
    a real pool of ~450 segments that turned a routine sweep into minutes of
    database work inside a one-minute schedule.
    """
    ids = {
        str(item)
        for item in db.scalars(
            select(DetectionFinding.target_id).where(
                DetectionFinding.target_type == "pcap",
                DetectionFinding.id.in_(
                    select(Alert.finding_id).where(
                        Alert.status.in_(["new", "acknowledged"]),
                        Alert.finding_id.is_not(None),
                    )
                ),
            )
        )
    }
    for evidence in db.scalars(select(Incident.evidence).where(Incident.status == "open")):
        pcap_id = (evidence or {}).get("pcap_id")
        if pcap_id:
            ids.add(str(pcap_id))
    return ids


def holds_open_case(db: Session, record: PcapRecord, open_ids: set[str] | None = None) -> bool:
    """True when an open alert or incident still points at this segment.

    ``open_ids`` lets a sweep reuse one lookup across every record; passing it is
    what keeps eviction linear in the number of segments.
    """
    ids = open_case_pcap_ids(db) if open_ids is None else open_ids
    return str(record.id) in ids


def release(db: Session, record: PcapRecord) -> int:
    """Delete one segment's file, keep its row; return the bytes actually freed."""
    path = Path(record.storage_path) if record.storage_path else None
    freed = 0
    if path is not None and path.exists():
        try:
            freed = path.stat().st_size
            path.unlink()
        except OSError:
            # A file we cannot remove must not abort the sweep: the next run
            # retries, and the rows we *can* free are worth freeing now.
            freed = 0
    record.retention_status = STATUS_RETAINED
    record.status = STATUS_RETAINED
    return freed


def _ordered_candidates(db: Session) -> tuple[list[PcapRecord], int]:
    """Segments whose file is still on disk, oldest first, unheld ones in front."""
    rows = db.scalars(
        select(PcapRecord).where(PcapRecord.storage_path != "").order_by(PcapRecord.id.asc())
    ).all()
    open_ids = open_case_pcap_ids(db)
    plain: list[PcapRecord] = []
    held: list[PcapRecord] = []
    for record in rows:
        if not Path(record.storage_path).exists():
            continue
        (held if str(record.id) in open_ids else plain).append(record)
    return plain + held, len(held)


def evict_oldest(
    db: Session,
    *,
    include_held: bool = True,
    stop_when_freed: int = 0,
    stop_under_bytes: int | None = None,
) -> dict[str, int]:
    """Delete the oldest segment files until a target is met.

    ``stop_when_freed`` is a byte target (0 = no target). ``stop_under_bytes``
    keeps the storage directory at or below that size, re-measured as files go.
    Candidates holding an open case are ordered last, so forensic payload is the
    last thing to go; ``include_held=False`` stops before touching any of them.
    """
    ordered, held_count = _ordered_candidates(db)
    if not include_held:
        ordered = ordered[: len(ordered) - held_count]
    freed = 0
    removed = 0
    # Measure the tree once. Re-walking it after every deleted file is what made
    # the sweep take minutes; ``freed`` is the *actual* size of each file this run
    # removed, so the running total is exact instead of an estimate that drifts.
    start = stored_bytes() if stop_under_bytes is not None else 0
    for record in ordered:
        if stop_when_freed and freed >= stop_when_freed:
            break
        if stop_under_bytes is not None and start - freed <= stop_under_bytes:
            break
        freed += release(db, record)
        removed += 1
    db.commit()
    return {
        "removed": removed,
        "freed_bytes": freed,
        "held": held_count,
        "skipped_held": 0 if include_held else held_count,
    }


def cleanup_expired(db: Session, cutoff: datetime) -> dict[str, int]:
    """Age sweep: retain every segment captured before ``cutoff``.

    Segments holding an open case are marked ``extended`` and keep their file;
    the space sweep is the only thing that can take those away.
    """
    rows = db.scalars(
        select(PcapRecord).where(
            PcapRecord.created_at < cutoff, PcapRecord.retention_status == STATUS_ACTIVE
        )
    ).all()
    extended = 0
    freed = 0
    removed = 0
    open_ids = open_case_pcap_ids(db)
    for record in rows:
        if str(record.id) in open_ids:
            record.retention_status = STATUS_EXTENDED
            extended += 1
            continue
        freed += release(db, record)
        removed += 1
    db.commit()
    return {"removed": removed, "extended": extended, "freed_bytes": freed}


def enforce_cap(db: Session) -> dict[str, int | str]:
    """Space sweep: keep the data partition out of the danger zone.

    Two targets, in order of urgency:

    1. the free-space floor - ingest is already stopped, and segments must go
       until the partition has headroom back. This is the only case allowed to
       drop segments that still hold an open case;
    2. ``PCAP_STORAGE_MAX_GB`` - routine trimming of the oldest segments.

    ``exhausted`` reports that nothing was freeable, so a directory filled by
    something other than segments is visible instead of looking like a clean run.
    """
    verdict = storage_guard.pressure()
    stored = stored_bytes()
    over_cap = stored > verdict["limit_bytes"]
    critical = verdict["state"] == "critical"
    if not over_cap and not critical:
        return {"removed": 0, "freed_bytes": 0, "exhausted": 0, "state": verdict["state"]}
    if critical:
        # Aim past the floor (floor + one GiB) so the next segment uploaded does
        # not trip the limit again immediately.
        target = max(0, stored - (verdict["floor_bytes"] - verdict["free_bytes"] + 1024 ** 3))
        if over_cap:
            target = min(target, verdict["limit_bytes"])
    else:
        target = verdict["limit_bytes"]
    result = evict_oldest(db, include_held=critical, stop_under_bytes=target)
    return {
        "removed": result["removed"],
        "freed_bytes": result["freed_bytes"],
        "held": result["held"],
        "exhausted": int(result["removed"] == 0 and result["held"] == 0),
        "state": verdict["state"],
    }
