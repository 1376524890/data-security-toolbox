"""AES-GCM encryption of SSH credentials at rest.

The deployment secret is injected through ``DEPLOYMENT_SECRET_KEY`` and is never
stored next to the database. Each encryption uses a fresh nonce and binds the
ciphertext to ``deployment_id``/``auth_type``/``key_id`` as AAD so a record can
never be replayed under a different identity.
"""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings


class CredentialError(Exception):
    pass


def _key_bytes() -> bytes:
    secret = settings.deployment_secret_key
    if not secret:
        raise CredentialError("DEPLOYMENT_SECRET_KEY is not configured")
    try:
        decoded = base64.b64decode(secret, validate=True)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    if len(digest) != 32:
        raise CredentialError("DEPLOYMENT_SECRET_KEY cannot derive a 256-bit key")
    return digest


def encrypt_credential(
    deployment_id: int,
    auth_type: str,
    secret: str,
    ttl_seconds: int | None = None,
) -> tuple[bytes, bytes, str, datetime | None]:
    """Return ``(ciphertext, nonce, key_id, expires_at)`` for the plaintext secret."""
    nonce = os.urandom(12)
    key_id = settings.deployment_key_id
    aad = f"{deployment_id}:{auth_type}:{key_id}".encode("utf-8")
    ciphertext = AESGCM(_key_bytes()).encrypt(nonce, secret.encode("utf-8"), aad)
    expires_at = datetime.now(UTC) + timedelta(seconds=ttl_seconds) if ttl_seconds else None
    return ciphertext, nonce, key_id, expires_at


def decrypt_credential(
    deployment_id: int,
    auth_type: str,
    key_id: str,
    nonce: bytes,
    ciphertext: bytes,
) -> str:
    aad = f"{deployment_id}:{auth_type}:{key_id}".encode("utf-8")
    try:
        plaintext = AESGCM(_key_bytes()).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # pragma: no cover - defensive
        raise CredentialError("credential decryption failed") from exc
    return plaintext.decode("utf-8")
