"""Candidate SHA256 fingerprints: proposed by a scan, accepted by a human.

A scan that finds a *high-risk* file can say "this exact content is dangerous",
but turning that into a rule by itself would let one bad match silently reshape
detection. So the hash is only recorded as a *candidate*; an operator accepts it
(one click) into a policy group - by default a group named after the task that
found it - and the default policy is never touched.

Candidates live in a SystemSetting row (same pattern as ``dlp_policy`` and
``sensitivity_levels``), so this needs no migration of its own; the fingerprints
themselves live on ``policy_groups.fingerprints``.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import PolicyGroup, SystemSetting

CANDIDATE_KEY = "fingerprint_candidates"
#: Only whole-content hashes are usable as a fingerprint.
SHA256 = re.compile(r"^[a-f0-9]{64}$")
#: Severities that make a file worth proposing as a fingerprint.
TRIGGER_SEVERITIES = {"Critical", "High"}


def _row(db: Session) -> SystemSetting:
    row = db.scalar(select(SystemSetting).where(SystemSetting.key == CANDIDATE_KEY))
    if row is None:
        row = SystemSetting(key=CANDIDATE_KEY, value={"items": []})
        db.add(row)
        db.flush()
    elif not isinstance(row.value, dict) or not isinstance(row.value.get("items"), list):
        row.value = {"items": []}
    return row


def _accepted_hashes(db: Session) -> set[str]:
    out: set[str] = set()
    for group in db.scalars(select(PolicyGroup)).all():
        out.update(str(item).lower() for item in (group.fingerprints or []))
    return out


def record(db: Session, *, sha256: str, path: str, name: str, source_name: str,
           level: str, severity: str, task_id: int | None) -> bool:
    """Propose one file as a fingerprint. Returns True when it was added.

    Only a whole-content SHA256 qualifies, only a high-risk finding is worth
    proposing, and a hash that is already accepted is never proposed again.
    """
    digest = str(sha256 or "").lower()
    if not SHA256.match(digest) or severity not in TRIGGER_SEVERITIES:
        return False
    if digest in _accepted_hashes(db):
        return False
    row = _row(db)
    items = row.value["items"]
    for item in items:
        if str(item.get("sha256", "")).lower() == digest:
            return False
    items.insert(0, {
        "sha256": digest, "path": path, "name": name, "source_name": source_name,
        "level": level, "severity": severity, "task_id": task_id,
        "status": "candidate", "group_name": "",
        "first_seen": datetime.now(UTC).isoformat(),
    })
    row.value = {"items": items[:500]}
    db.flush()
    return True


def list_candidates(db: Session, *, status: str | None = None) -> list[dict[str, Any]]:
    items = list((_row(db).value or {}).get("items") or [])
    if status:
        items = [item for item in items if item.get("status") == status]
    return items


def _find(items: list[dict[str, Any]], sha256: str) -> dict[str, Any] | None:
    digest = str(sha256).lower()
    return next((item for item in items if str(item.get("sha256", "")).lower() == digest), None)


def accept(db: Session, sha256: str, *, group_name: str = "", actor: str = "admin") -> dict[str, Any]:
    """One click: put the hash into a policy group, never into the default policy.

    With no explicit name the group is named after the task that found it
    (``任务 #7 指纹``), so one investigation's hashes stay together and a later
    task does not inherit them.
    """
    digest = str(sha256).lower()
    if not SHA256.match(digest):
        raise ValueError("不是合法的 SHA256")
    row = _row(db)
    item = _find(row.value["items"], digest)
    if item is None:
        raise ValueError("候选指纹不存在")
    name = (group_name or "").strip() or (
        f"任务 #{item['task_id']} 指纹" if item.get("task_id") else "手工确认指纹")
    group = db.scalar(select(PolicyGroup).where(PolicyGroup.name == name))
    if group is None:
        group = PolicyGroup(name=name, description=f"由 {item.get('path') or '扫描结果'} 确认的指纹规则集",
                            scope=["file", "network"], fingerprints=[], created_by=actor)
        db.add(group)
        db.flush()
    hashes = [str(value).lower() for value in (group.fingerprints or [])]
    if digest not in hashes:
        group.fingerprints = [*hashes, digest]
        group.version = int(group.version or 1) + 1
    item["status"] = "accepted"
    item["group_name"] = group.name
    row.value = {"items": row.value["items"]}
    db.commit()
    return {"sha256": digest, "group_id": group.id, "group_name": group.name}


def ignore(db: Session, sha256: str) -> dict[str, Any]:
    digest = str(sha256).lower()
    row = _row(db)
    item = _find(row.value["items"], digest)
    if item is None:
        raise ValueError("候选指纹不存在")
    item["status"] = "ignored"
    row.value = {"items": row.value["items"]}
    db.commit()
    return {"sha256": digest, "status": "ignored"}
