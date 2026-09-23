"""Synchronous target helpers for the task wizard: reachability and directory tree.

Both endpoints are admin-only and never persist a credential — the wizard uses
them to prove a host is reachable and to let the operator tick a scope. The SSH
transport is the same one probe deployment uses, so the browse path is not a
weaker way into a host than a deployment.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.security import require_active_admin
from app.models import User
from app.services import target_tree
from app.services.target_tree import TargetError

router = APIRouter(tags=["targets"])


class TargetSpec(BaseModel):
    protocol: str = Field(default="ssh", max_length=16)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="root", max_length=128)
    auth_type: str = Field(default="password", max_length=32)
    password: str | None = Field(default=None, max_length=512)
    private_key: str | None = Field(default=None, max_length=16384)
    key_passphrase: str | None = Field(default=None, max_length=512)
    roots: list[str] = Field(default_factory=list, max_length=16)
    #: 0 = no cap. The picker expands one level per call, so a deep tree is walked
    #: on demand rather than cut off at a fixed depth (it used to stop at 3).
    max_depth: int = Field(default=0, ge=0, le=target_tree.MAX_DEPTH)
    max_entries: int = Field(default=0, ge=0, le=target_tree.MAX_ENTRIES)


def _spec(payload: TargetSpec) -> dict:
    if payload.protocol != "ssh":
        raise HTTPException(400, f"暂不支持的目标协议: {payload.protocol}")
    if payload.auth_type not in {"password", "private_key"}:
        raise HTTPException(400, "连接方式只支持 password 或 private_key")
    return payload.model_dump()


@router.post("/targets/test")
def test_target(payload: TargetSpec, user: User = Depends(require_active_admin)) -> dict:
    """Open one connection to prove reachability; the credential is not stored."""
    return target_tree.test_ssh(_spec(payload))


@router.post("/targets/browse")
def browse_target(payload: TargetSpec, user: User = Depends(require_active_admin)) -> dict:
    """Synchronous directory listing for the scope picker; 0 means no cap."""
    try:
        return target_tree.browse_ssh(_spec(payload), roots=payload.roots,
                                      max_depth=payload.max_depth, max_entries=payload.max_entries)
    except TargetError as exc:
        raise HTTPException(400, str(exc)) from exc
