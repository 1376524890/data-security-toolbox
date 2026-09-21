"""Policy-group CRUD: the rule bundles an operator selects at task dispatch.

The rules themselves live in the shared rule library; a group only references
their identifiers and adds categories/keywords/thresholds. Task dispatch reads a
group through this surface and stores the resolved snapshot, so this module stays
the single place that writes the group table.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_session_user
from app.models import PolicyGroup, Task
from app.services import policy_groups as groups
from app.services.policy_groups import PolicyGroupError

router = APIRouter(tags=["policy-groups"])

#: Whitelisted sort keys; anything else is rejected instead of interpolated.
SORTABLE = {"id": PolicyGroup.id, "name": PolicyGroup.name, "version": PolicyGroup.version,
            "updated_at": PolicyGroup.updated_at, "created_at": PolicyGroup.created_at}


class GroupPayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    enabled: bool = True
    scope: list[str] = Field(default_factory=list, max_length=3)
    rule_ids: list[str] = Field(default_factory=list, max_length=512)
    categories: list[str] = Field(default_factory=list, max_length=256)
    keywords: list[str] = Field(default_factory=list, max_length=256)
    min_confidence: float = 0.6
    min_matches: int = 1


class GroupPatch(BaseModel):
    """Every field optional: a PATCH changes only what it sends."""

    name: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    enabled: bool | None = None
    scope: list[str] | None = None
    rule_ids: list[str] | None = None
    categories: list[str] | None = None
    keywords: list[str] | None = None
    min_confidence: float | None = None
    min_matches: int | None = None


def _actor(db: Session, request: Request) -> str:
    try:
        user = get_session_user(db, request)
    except Exception:
        user = None
    return str(getattr(user, "username", "") or "admin")


def _referenced_by_open_task(db: Session, group_id: int) -> bool:
    """True when an unfinished task snapshotted this group in its payload.

    Tasks store ids in ``payload['policy_group_ids']``; membership is checked in
    Python so the same code works on the JSON column without a dialect-specific
    containment operator.
    """
    rows = db.scalars(select(Task).where(Task.status.in_(("Pending", "Running"))))
    for task in rows:
        ids = (task.payload or {}).get("policy_group_ids") or []
        if group_id in [int(item) for item in ids if str(item).isdigit()]:
            return True
    return False


@router.get("/policy-groups")
def list_groups(enabled: bool | None = Query(default=None),
                name: str = Query(default="", max_length=128),
                sort: str = Query(default="id"), order: str = Query(default="desc"),
                page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                db: Session = Depends(get_db)) -> dict:
    if sort not in SORTABLE:
        raise HTTPException(400, f"不支持的排序字段: {sort}")
    query = select(PolicyGroup)
    if enabled is not None:
        query = query.where(PolicyGroup.enabled.is_(enabled))
    if name:
        query = query.where(PolicyGroup.name.ilike(f"%{name}%"))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    column = SORTABLE[sort]
    query = query.order_by(column.desc() if order == "desc" else column.asc())
    rows = db.scalars(query.offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [groups.serialize(row) for row in rows], "total": total,
            "page": page, "page_size": page_size}


@router.post("/policy-groups")
def create_group(payload: GroupPayload, request: Request, db: Session = Depends(get_db)) -> dict:
    values = payload.model_dump()
    name = values.pop("name")
    if db.scalar(select(PolicyGroup.id).where(PolicyGroup.name == name)):
        raise HTTPException(409, "同名策略组已存在")
    try:
        clean = groups.validate(values)
    except PolicyGroupError as exc:
        raise HTTPException(400, str(exc)) from exc
    group = PolicyGroup(name=name, version=1, created_by=_actor(db, request), **clean)
    db.add(group)
    db.commit()
    db.refresh(group)
    return groups.serialize(group)


@router.get("/policy-groups/{group_id}")
def get_group(group_id: int, db: Session = Depends(get_db)) -> dict:
    group = db.get(PolicyGroup, group_id)
    if group is None:
        raise HTTPException(404, "policy group not found")
    return groups.serialize(group)


@router.patch("/policy-groups/{group_id}")
def update_group(group_id: int, payload: GroupPatch, db: Session = Depends(get_db)) -> dict:
    group = db.get(PolicyGroup, group_id)
    if group is None:
        raise HTTPException(404, "policy group not found")
    supplied = {key: value for key, value in payload.model_dump(exclude_unset=True).items()
                if value is not None}
    if not supplied:
        return groups.serialize(group)
    if "name" in supplied and supplied["name"] != group.name:
        clash = db.scalar(select(PolicyGroup.id).where(PolicyGroup.name == supplied["name"],
                                                       PolicyGroup.id != group_id))
        if clash:
            raise HTTPException(409, "同名策略组已存在")
    try:
        clean = groups.validate(supplied)
    except PolicyGroupError as exc:
        raise HTTPException(400, str(exc)) from exc
    groups.apply_values(group, clean)
    # The revision moves so an operator can tell two edits apart; a task that
    # already ran keeps the snapshot it was queued with.
    group.version = int(group.version or 1) + 1
    db.commit()
    db.refresh(group)
    return groups.serialize(group)


@router.delete("/policy-groups/{group_id}")
def delete_group(group_id: int, db: Session = Depends(get_db)) -> dict:
    group = db.get(PolicyGroup, group_id)
    if group is None:
        raise HTTPException(404, "policy group not found")
    if _referenced_by_open_task(db, group_id):
        raise HTTPException(409, "该策略组仍被未完成的任务引用，请先取消任务")
    db.delete(group)
    db.commit()
    return {"status": "deleted"}
