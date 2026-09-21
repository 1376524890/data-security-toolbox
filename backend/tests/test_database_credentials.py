"""Database credentials: AES-GCM at rest, its own key and AAD."""
from __future__ import annotations

import base64
import hashlib

import pytest
from app.core.config import settings
from app.services.database_scan import credentials


def test_password_round_trips_and_never_appears_in_the_ciphertext() -> None:
    ciphertext, nonce, key_id = credentials.encrypt_password(7, "dst_ro", "s3cr3t-密码-A1")
    assert ciphertext and nonce and len(nonce) == 12
    assert key_id == settings.database_credential_key_id
    assert b"s3cr3t" not in ciphertext
    assert credentials.decrypt_password(7, "dst_ro", key_id, nonce, ciphertext) == "s3cr3t-密码-A1"


def test_an_empty_password_is_stored_as_no_secret() -> None:
    ciphertext, nonce, key_id = credentials.encrypt_password(7, "dst_ro", "")
    assert (ciphertext, nonce) == (None, None)
    assert key_id == settings.database_credential_key_id
    assert credentials.decrypt_password(7, "dst_ro", key_id, None, None) == ""


@pytest.mark.parametrize(
    ("connection_id", "username", "key_id"),
    [
        (8, "dst_ro", "dbc1"),
        (7, "other_user", "dbc1"),
        (7, "dst_ro", "dbc2"),
    ],
)
def test_the_ciphertext_is_bound_to_its_connection_identity(
    connection_id: int, username: str, key_id: str
) -> None:
    ciphertext, nonce, sealed_key = credentials.encrypt_password(7, "dst_ro", "pw-1")
    with pytest.raises(credentials.CredentialError):
        credentials.decrypt_password(connection_id, username, key_id, nonce, ciphertext)
    assert sealed_key == "dbc1"


def test_a_different_key_cannot_decrypt_an_existing_password(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_credential_key", "")
    ciphertext, nonce, key_id = credentials.encrypt_password(3, "root", "top-secret")
    monkeypatch.setattr(settings, "database_credential_key", "another-key-entirely")
    with pytest.raises(credentials.CredentialError):
        credentials.decrypt_password(3, "root", key_id, nonce, ciphertext)


def test_a_base64_key_is_used_verbatim_and_any_other_string_is_hashed(monkeypatch) -> None:
    raw = base64.b64encode(bytes(range(32))).decode()
    monkeypatch.setattr(settings, "database_credential_key", raw)
    assert credentials._key_bytes() == bytes(range(32))
    monkeypatch.setattr(settings, "database_credential_key", "not-base64!!")
    assert credentials._key_bytes() == hashlib.sha256(
        b"dst/database-credential/v1" + b"not-base64!!"
    ).digest()
    assert credentials._key_bytes() != credentials._DOMAIN


def test_the_database_key_is_not_the_platform_secret(monkeypatch) -> None:
    """The two keys are derived with different labels, so one cannot stand in
    for the other even when the deployment only set SECRET_KEY."""
    monkeypatch.setattr(settings, "database_credential_key", "")
    monkeypatch.setattr(settings, "secret_key", "shared-secret")
    derived = credentials._key_bytes()
    assert derived != hashlib.sha256(b"shared-secret").digest()
    assert derived == hashlib.sha256(
        b"dst/database-credential/v1" + b"shared-secret"
    ).digest()


def test_without_any_configured_key_encryption_refuses_to_run(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_credential_key", "")
    monkeypatch.setattr(settings, "secret_key", "")
    with pytest.raises(credentials.CredentialError):
        credentials.encrypt_password(1, "root", "pw")
