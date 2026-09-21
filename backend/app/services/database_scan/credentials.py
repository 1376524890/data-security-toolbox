"""AES-GCM encryption of target-database passwords at rest.

The SSH deployment secret and this key are deliberately separate: different
lifetime, different AAD. ``DATABASE_CREDENTIAL_KEY`` should be a base64 32-byte
value (or any string, which is then hashed with a domain-separation label); when
it is absent the key is derived from ``SECRET_KEY`` with that same label, so a
missing value weakens separation rather than breaking the stack.

AAD binds the ciphertext to the connection and the account it belongs to, so a
stored password can never be replayed under another connection's identity.
An empty password is *not* encrypted: it is stored as "no secret", which keeps
unix_socket/peer-style accounts representable without inventing a value.
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

_DOMAIN = b"dst/database-credential/v1"


class CredentialError(Exception):
    """The stored password cannot be decrypted, or no key is configured."""


def _key_bytes() -> bytes:
    secret = (settings.database_credential_key or "").strip()
    if secret:
        try:
            decoded = base64.b64decode(secret, validate=True)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        return hashlib.sha256(_DOMAIN + secret.encode("utf-8")).digest()
    base = (settings.secret_key or "").strip()
    if not base:
        raise CredentialError("neither DATABASE_CREDENTIAL_KEY nor SECRET_KEY is configured")
    return hashlib.sha256(_DOMAIN + base.encode("utf-8")).digest()


def _aad(connection_id: int, username: str, key_id: str) -> bytes:
    return f"db:{connection_id}:{username}:{key_id}".encode()


def encrypt_password(
    connection_id: int, username: str, password: str
) -> tuple[bytes | None, bytes | None, str]:
    """Return ``(ciphertext, nonce, key_id)``; ``None`` when no password is set."""
    key_id = settings.database_credential_key_id
    if not password:
        return None, None, key_id
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key_bytes()).encrypt(nonce, password.encode("utf-8"),
                                             _aad(connection_id, username, key_id))
    return ciphertext, nonce, key_id


def decrypt_password(
    connection_id: int,
    username: str,
    key_id: str,
    nonce: bytes | None,
    ciphertext: bytes | None,
) -> str:
    """The plaintext password for one connection; empty when none is stored."""
    if not ciphertext or not nonce:
        return ""
    try:
        plaintext = AESGCM(_key_bytes()).decrypt(
            bytes(nonce), bytes(ciphertext), _aad(connection_id, username, key_id or "")
        )
    except Exception as exc:
        raise CredentialError(
            f"stored password for connection {connection_id} cannot be decrypted"
        ) from exc
    return plaintext.decode("utf-8")
