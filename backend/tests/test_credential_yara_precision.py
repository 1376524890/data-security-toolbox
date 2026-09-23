r"""The YARA credential rule must not fire on binary noise.

``SensitiveCredential`` used to look for ``password\s*[=:]\s*[^\s]+``, and
``[^\s]+`` matched arbitrary bytes: every one of the 382 findings it raised on a
live host sat on the platform's own 65 MiB packet captures, where the byte soup
after a chance ``password:`` is not a credential. The rule still reads captures --
a credential in the payload is worth reporting -- but it now requires the shape of
a config line, which is what a credential value actually looks like.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.engine.data_engine.engine import yara_scan

RULE_DIR = Path(__file__).resolve().parents[1] / "app/rules/data"

#: Bytes a capture is full of. Each of these matched the old ``[^\s]+``.
BINARY_NOISE = (
    b"\x7f\x03password:\x01\x02\x03\x04\x05\x06\x07\x08\xff",
    b"secret=" + bytes(range(0, 32)),
    bytes(bytearray([(index * 37 + 11) % 256 for index in range(4096)])) + b"password:\x00\x01",
    b"...password:AAAAAAAAAAAAAA\x01\x02",
)

#: What a credential in a file really looks like.
CREDENTIAL_LINES = (
    b"[db]\npassword = S3cretValue123\nurl = https://x/y\n",
    b"password = S3cretValue123\r\n",
    b"AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n",
)


def _matches(path: Path) -> set[str]:
    hits = yara_scan(path, RULE_DIR)
    return {hit["rule"] for hit in hits if hit["rule"] == "SensitiveCredential"}


def test_binary_capture_bytes_are_not_a_credential(tmp_path) -> None:
    pytest.importorskip("yara")

    for index, sample in enumerate(BINARY_NOISE):
        target = tmp_path / f"noise-{index}.bin"
        target.write_bytes(sample)
        assert _matches(target) == set(), sample


def test_a_config_line_is_still_a_credential(tmp_path) -> None:
    pytest.importorskip("yara")

    for index, sample in enumerate(CREDENTIAL_LINES):
        target = tmp_path / f"credential-{index}.conf"
        target.write_bytes(sample)
        assert _matches(target) == {"SensitiveCredential"}, sample


def test_a_capture_sized_file_is_not_scanned_for_a_text_credential(tmp_path) -> None:
    """The same bound the sibling rules use: a 65 MiB capture is not a document."""
    pytest.importorskip("yara")
    target = tmp_path / "big.conf"
    with target.open("wb") as handle:
        handle.write(CREDENTIAL_LINES[0])
        handle.seek(21 * 1024 * 1024 - 1)
        handle.write(b"\0")

    assert _matches(target) == set()
