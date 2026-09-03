from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import AdminSession, Probe, User

PBKDF2_ITERATIONS = 210_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    if not token or not token_hash:
        return False
    return hmac.compare_digest(hash_token(token), token_hash)


def ensure_admin(db: Session) -> None:
    if settings.app_env == "production" and not settings.admin_password:
        raise RuntimeError("ADMIN_PASSWORD is required in production")
    user = db.scalar(select(User).where(User.username == settings.admin_username))
    if user:
        if not user.password_hash:
            user.password_hash = hash_password(settings.admin_password or "ChangeMe123!")
            db.commit()
        return user
    password = settings.admin_password or "ChangeMe123!"
    db.add(User(username=settings.admin_username, role="admin", is_active=True, password_hash=hash_password(password)))
    db.commit()
    return db.scalar(select(User).where(User.username == settings.admin_username))


def create_admin_session(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(hours=12)
    db.add(AdminSession(user_id=user.id, token_hash=hash_token(token), expires_at=expires_at))
    db.commit()
    return token


def set_admin_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,
        secure=settings.cookie_secure or settings.app_env == "production",
        samesite="strict",
        max_age=12 * 60 * 60,
        path="/",
    )


def clear_admin_cookie(response: Response) -> None:
    response.delete_cookie(settings.cookie_name, path="/")


def get_session_user(db: Session, request: Request) -> User | None:
    token = request.cookies.get(settings.cookie_name)
    if not token:
        return None
    session = db.scalar(select(AdminSession).where(AdminSession.token_hash == hash_token(token)))
    if not session or session.expires_at < datetime.now(UTC):
        return None
    return db.get(User, session.user_id)


def require_admin(request: Request, db: Session) -> User:
    if settings.app_env != "production":
        return ensure_admin(db)
    user = get_session_user(db, request)
    if not user or user.role not in {"admin", "operator"}:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="admin authentication required")
    return user


def require_probe(db: Session, probe_id: int | None, token: str | None) -> Probe:
    if settings.app_env != "production" and not token:
        # Development convenience for existing tests and local UI uploads.
        if probe_id:
            probe = db.get(Probe, probe_id)
            if probe:
                return probe
        return None  # type: ignore[return-value]
    if not probe_id or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="probe authentication required")
    probe = db.get(Probe, probe_id)
    if not probe or not verify_token(token, probe.token_hash or probe.token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid probe token")
    return probe


def require_probe_headers(request: Request, db: Session) -> Probe:
    raw_id = request.headers.get("X-Probe-ID")
    token = request.headers.get("X-Probe-Token")
    try:
        probe_id = int(raw_id) if raw_id else None
    except ValueError:
        probe_id = None
    return require_probe(db, probe_id, token)


def mask_secret(value: str | None) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}***{value[-4:]}"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        result = dict(value)
        for key in ("token", "password", "secret", "api_key", "webhook_secret", "probe_token", "misp_api_key"):
            if key in result:
                result[key] = mask_secret(str(result[key]))
            elif key in {k.lower() for k in result}:
                result[key] = mask_secret(str(result[key]))
        return result
    return value
