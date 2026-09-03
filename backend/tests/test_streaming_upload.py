from __future__ import annotations

import pytest

from app.core.storage import stream_to_storage


class FakeUpload:
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks
        self.index = 0

    async def read(self, size: int = -1):
        if self.index >= len(self.chunks):
            return b""
        chunk = self.chunks[self.index]
        self.index += 1
        return chunk


def test_stream_to_storage_atomic(tmp_path, monkeypatch) -> None:
    from app.core.config import settings
    monkeypatch.setattr(settings, "storage_dir", tmp_path)
    result = await_result(stream_to_storage(FakeUpload([b"a" * 1024, b"b" * 1024]), "sample.bin", subdir="uploads", max_bytes=10 * 1024 * 1024))
    assert result["size"] == 2048
    assert len(result["sha256"]) == 64
    assert not list(tmp_path.rglob("*.partial"))


def test_stream_to_storage_rejects_over_limit(tmp_path, monkeypatch) -> None:
    from app.core.config import settings
    monkeypatch.setattr(settings, "storage_dir", tmp_path)
    with pytest.raises(ValueError, match="upload_too_large"):
        await_result(stream_to_storage(FakeUpload([b"x" * 2048]), "large.bin", subdir="uploads", max_bytes=1024))
    assert not list(tmp_path.rglob("*.partial"))
    assert not list(tmp_path.rglob("large.bin"))


def await_result(coro):
    import asyncio
    return asyncio.run(coro)
