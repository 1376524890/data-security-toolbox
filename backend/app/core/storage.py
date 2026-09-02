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


def safe_path(base: Path, filename: str) -> Path:
    resolved_base = base.resolve()
    target = (resolved_base / safe_name(filename)).resolve()
    if not target.is_relative_to(resolved_base):
        raise ValueError("invalid path")
    return target

