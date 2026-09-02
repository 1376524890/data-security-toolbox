import hashlib
from pathlib import Path

from app.services.metadata_service import detect_file_type, extract_metadata, sha256_file


def test_detect_file_type(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"
    path.write_bytes(b"hello")
    assert detect_file_type(path).startswith("application/octet-stream")


def test_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"data")
    assert sha256_file(path) == hashlib.sha256(b"data").hexdigest()


def test_extract_unsupported_metadata(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"
    path.write_bytes(b"plain text")
    result = extract_metadata(path)
    assert result["sha256"] == hashlib.sha256(b"plain text").hexdigest()
    assert result["metadata"]["unsupported"] is True

