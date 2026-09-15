import pytest

from app.deployment.credential import decrypt_credential, encrypt_credential


def test_roundtrip() -> None:
    ciphertext, nonce, key_id, expires = encrypt_credential(1, "password", "s3cret", 3600)
    assert key_id
    assert expires is not None
    assert decrypt_credential(1, "password", key_id, nonce, ciphertext) == "s3cret"


def test_aad_binds_deployment() -> None:
    ciphertext, nonce, key_id, _ = encrypt_credential(1, "password", "s3cret", 3600)
    with pytest.raises(Exception):
        decrypt_credential(2, "password", key_id, nonce, ciphertext)


def test_tamper_rejected() -> None:
    ciphertext, nonce, key_id, _ = encrypt_credential(1, "password", "s3cret", 3600)
    with pytest.raises(Exception):
        decrypt_credential(1, "password", key_id, nonce, ciphertext[:-1] + b"\x00")
