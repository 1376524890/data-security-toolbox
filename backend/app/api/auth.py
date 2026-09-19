# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Admin console sessions: password login, logout and the current identity.

The console authenticates with a session cookie (or the matching bearer token)
and ``/auth/me`` is the identity read the frontend performs on every load.  The
non-production shortcut through ``ensure_admin`` is part of the existing
contract and is kept verbatim.  Session storage, cookie handling and token
hashing stay in ``app.core.security`` and the ``AdminSession`` model; this
module owns paths and response shapes only.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    clear_admin_cookie,
    create_admin_session,
    ensure_admin,
    hash_token,
    set_admin_cookie,
    verify_password,
)
from app.models import AdminSession, User
from app.schemas import LoginRequest

router = APIRouter()


@router.post("/auth/login")
def admin_login(
    payload: LoginRequest, response: Response, db: Session = Depends(get_db)
) -> dict[str, Any]:
    ensure_admin(db)
    user = db.scalar(select(User).where(User.username == payload.username))
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "invalid username or password")
    token = create_admin_session(db, user)
    set_admin_cookie(response, token)
    return {"id": user.id, "username": user.username, "role": user.role}


@router.post("/auth/logout")
def admin_logout(
    response: Response, request: Request, db: Session = Depends(get_db)
) -> dict[str, str]:
    token = request.cookies.get(settings.cookie_name)
    if token:
        row = db.scalar(select(AdminSession).where(AdminSession.token_hash == hash_token(token)))
        if row:
            db.delete(row)
            db.commit()
    clear_admin_cookie(response)
    return {"status": "ok"}


@router.get("/auth/me")
def admin_me(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    if settings.app_env != "production":
        user = ensure_admin(db)
        return {"id": user.id, "username": user.username, "role": user.role}
    token = request.cookies.get(settings.cookie_name)
    if not token:
        raise HTTPException(401, "not authenticated")
    row = db.scalar(select(AdminSession).where(AdminSession.token_hash == hash_token(token)))
    if not row:
        raise HTTPException(401, "not authenticated")
    user = db.get(User, row.user_id)
    if not user:
        raise HTTPException(401, "not authenticated")
    return {"id": user.id, "username": user.username, "role": user.role}
