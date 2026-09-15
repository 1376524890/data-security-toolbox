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
    assert result["metadata"]["preview"] == "plain text"


def test_png_appended_data(tmp_path: Path) -> None:
    from PIL import Image
    path = tmp_path / "image.png"
    Image.new("RGB", (4, 3)).save(path)
    assert extract_metadata(path)["hidden_info"]["hidden"] is False
    original_size = path.stat().st_size
    with path.open("ab") as handle:
        handle.write("隐写数据test".encode("gb18030"))
    result = extract_metadata(path)
    assert result["metadata"]["width"] == 4
    finding = result["hidden_info"]["findings"][0]
    assert finding["offset"] == original_size
    assert finding["preview"] == "隐写数据test"


def test_png_truncated_chunk_is_not_trailing_data(tmp_path: Path) -> None:
    from app.services.metadata_service import hidden_info
    path = tmp_path / "broken.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + (100).to_bytes(4, "big") + b"IDAT\x00\x00\x00\x00IEND\xaeB`\x82payload")
    assert not hidden_info(path, "image/png", {})["hidden"]

