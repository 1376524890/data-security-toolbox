import os
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from app.core.config import settings


def safe_name(filename: str) -> str:
    name = Path(filename).name.replace("..", "").strip()
    return name or "upload.bin"


def save_bytes(data: bytes, filename: str, subdir: str = "uploads") -> Path:
    target_dir = settings.storage_dir / subdir
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{uuid4().hex}_{safe_name(filename)}"
    target.write_bytes(data)
    return target


async def stream_to_storage(
    file,
    filename: str,
    subdir: str = "uploads",
    max_bytes: int = 0,
    chunk_size: int = 1024 * 1024,
) -> dict[str, object]:
    """Stream an UploadFile-like object to storage with atomic rename.

    The caller supplies an object with ``await file.read(size)``. The file is
    written to a ``.partial`` path, fsynced, then renamed atomically.
    """
    target_dir = settings.storage_dir / subdir
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{uuid4().hex}_{safe_name(filename)}"
    partial = target.with_name(target.name + ".partial")
    digest = sha256()
    total = 0
    try:
        with partial.open("wb") as handle:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
                handle.write(chunk)
                if max_bytes and total > max_bytes:
                    raise ValueError("upload_too_large")
                handle.flush()
                os.fsync(handle.fileno())
        partial.replace(target)
        return {"path": target, "size": total, "sha256": digest.hexdigest()}
    except Exception:
        if partial.exists():
            partial.unlink()
        if target.exists() and total > 0:
            target.unlink()
        raise


def safe_path(base: Path, filename: str) -> Path:
    resolved_base = base.resolve()
    target = (resolved_base / safe_name(filename)).resolve()
    if not target.is_relative_to(resolved_base):
        raise ValueError("invalid path")
    return target
