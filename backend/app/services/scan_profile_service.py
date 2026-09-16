"""ScanProfile defaults, validation and the immutable per-task snapshot.

A profile is the versioned, reusable scan configuration. A queued task stores the
*resolved* configuration it was created with, so editing a profile afterwards
cannot silently change the scope of work a probe has already been handed.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ScanProfile

from shared.scanning.budget import DEFAULT_LIMITS  # noqa: E402


class ScanProfileError(ValueError):
    """The profile cannot be stored or turned into a probe configuration."""


#: Server-side defaults. Sourced from the shared budget so the probe and the
#: platform cannot drift apart on what "unconfigured" means.
DEFAULT_SCOPE: dict[str, Any] = {
    "include_paths": [],
    "exclude_paths": [],
    "file_types": [],
    "enabled": True,
    "scheduled": False,
    "interval_seconds": 3600,
}

#: Fields a caller may set, mapped to (type, minimum, maximum). Values outside the
#: range are rejected rather than clamped, so an operator sees the mistake.
NUMERIC_BOUNDS: dict[str, tuple[type, float, float]] = {
    "max_files": (int, 1, DEFAULT_LIMITS["max_files_ceiling"]),
    "max_dirs": (int, 1, 100_000),
    "max_depth": (int, 0, DEFAULT_LIMITS["max_depth_ceiling"]),
    "max_runtime_seconds": (int, 5, DEFAULT_LIMITS["max_runtime_ceiling"]),
    "max_bytes_read": (int, 1024, 16 * 1024 * 1024 * 1024),
    "max_single_file_size": (int, 1024, 1024 * 1024 * 1024),
    # Full hashing is expensive, so the ceiling is deliberately far below "any size".
    "max_full_hash_size": (int, 0, 128 * 1024 * 1024),
    "sample_block_size": (int, 4096, 8 * 1024 * 1024),
    "max_sample_rows": (int, 1, 1000),
    "max_cpu_seconds": (float, 0, 86_400),
    "max_rss_mb": (float, 0, 65536),
    "xlsx_max_entries": (int, 1, 100_000),
    "xlsx_max_uncompressed_bytes": (int, 1024, 4 * 1024 * 1024 * 1024),
    "xlsx_max_compression_ratio": (float, 1, 100_000),
    "xlsx_max_shared_strings": (int, 1, 10_000_000),
    "xlsx_max_sheets": (int, 1, 1024),
    "xlsx_max_columns": (int, 1, 4096),
    "xlsx_max_rows": (int, 1, 100_000),
    "interval_seconds": (int, 60, 30 * 24 * 3600),
}

BOOLEAN_FIELDS = ("large_file_sampling", "enabled", "scheduled")
LIST_FIELDS = ("include_paths", "exclude_paths", "file_types")

#: The full column set, so a snapshot exposes every knob explicitly.
PROFILE_FIELDS = ("include_paths", "exclude_paths", "file_types", *NUMERIC_BOUNDS, *BOOLEAN_FIELDS)


def default_values() -> dict[str, Any]:
    values: dict[str, Any] = {**DEFAULT_SCOPE}
    for name, default in (
        ("max_files", DEFAULT_LIMITS["max_files"]),
        ("max_dirs", DEFAULT_LIMITS["max_dirs"]),
        ("max_depth", DEFAULT_LIMITS["max_depth"]),
        ("max_runtime_seconds", DEFAULT_LIMITS["max_runtime_seconds"]),
        ("max_bytes_read", DEFAULT_LIMITS["max_bytes_read"]),
        ("max_single_file_size", DEFAULT_LIMITS["max_single_file_size"]),
        ("max_full_hash_size", DEFAULT_LIMITS["max_full_hash_size"]),
        ("large_file_sampling", DEFAULT_LIMITS["large_file_sampling"]),
        ("sample_block_size", DEFAULT_LIMITS["sample_block_size"]),
        ("max_sample_rows", DEFAULT_LIMITS["max_sample_rows"]),
        ("max_cpu_seconds", DEFAULT_LIMITS["max_cpu_seconds"]),
        ("max_rss_mb", DEFAULT_LIMITS["max_rss_mb"]),
        ("xlsx_max_entries", DEFAULT_LIMITS["xlsx_max_entries"]),
        ("xlsx_max_uncompressed_bytes", DEFAULT_LIMITS["xlsx_max_uncompressed_bytes"]),
        ("xlsx_max_compression_ratio", DEFAULT_LIMITS["xlsx_max_compression_ratio"]),
        ("xlsx_max_shared_strings", DEFAULT_LIMITS["xlsx_max_shared_strings"]),
        ("xlsx_max_sheets", DEFAULT_LIMITS["xlsx_max_sheets"]),
        ("xlsx_max_columns", DEFAULT_LIMITS["xlsx_max_columns"]),
        ("xlsx_max_rows", DEFAULT_LIMITS["xlsx_max_rows"]),
    ):
        values[name] = default
    return values


def validate(values: dict[str, Any]) -> dict[str, Any]:
    """Type- and range-check the supplied fields; unknown keys are rejected."""
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if key in LIST_FIELDS:
            if not isinstance(value, list):
                raise ScanProfileError(f"{key} 必须是数组")
            items = [str(item).strip() for item in value if str(item).strip()]
            if key != "file_types":
                for item in items:
                    if len(item) > 512 or not item.startswith("/") or ".." in item.split("/"):
                        raise ScanProfileError(f"{key} 只允许绝对 Linux 路径且不含 '..': {item}")
            cleaned[key] = list(dict.fromkeys(items))[:64]
        elif key in BOOLEAN_FIELDS:
            cleaned[key] = bool(value)
        elif key in NUMERIC_BOUNDS:
            caster, low, high = NUMERIC_BOUNDS[key]
            try:
                number = caster(value)
            except (TypeError, ValueError) as exc:
                raise ScanProfileError(f"{key} 必须是数字") from exc
            if number < low or number > high:
                raise ScanProfileError(f"{key} 必须在 {low} 与 {high} 之间")
            cleaned[key] = number
        elif key in {"name", "description"}:
            cleaned[key] = str(value)[:512]
        else:
            raise ScanProfileError(f"未知字段: {key}")
    return cleaned


def serialize(profile: ScanProfile) -> dict[str, Any]:
    payload = {"id": profile.id, "name": profile.name, "version": profile.version,
               "description": profile.description, "created_by": profile.created_by,
               "created_at": profile.created_at.isoformat() if profile.created_at else "",
               "updated_at": profile.updated_at.isoformat() if profile.updated_at else ""}
    for field in PROFILE_FIELDS:
        payload[field] = getattr(profile, field)
    return payload


def snapshot(profile: ScanProfile) -> dict[str, Any]:
    """The configuration a task should run with.

    Scope fields the probe does not understand yet (excludes, file types) are kept
    in the payload so the platform records what was actually requested; the probe
    applies the ones it supports and reports its own coverage.
    """
    payload = {field: getattr(profile, field) for field in PROFILE_FIELDS}
    payload["profile_id"] = profile.id
    payload["profile_name"] = profile.name
    payload["profile_version"] = profile.version
    return payload


def probe_config(snapshot_payload: dict[str, Any]) -> dict[str, Any]:
    """Translate a task snapshot into the probe's ``config`` dictionary."""
    return {
        "paths": list(snapshot_payload.get("include_paths") or []),
        "exclude_paths": list(snapshot_payload.get("exclude_paths") or []),
        "file_types": list(snapshot_payload.get("file_types") or []),
        "max_files": int(snapshot_payload.get("max_files", DEFAULT_LIMITS["max_files"])),
        "max_depth": int(snapshot_payload.get("max_depth", DEFAULT_LIMITS["max_depth"])),
        "max_dirs": int(snapshot_payload.get("max_dirs", DEFAULT_LIMITS["max_dirs"])),
        "timeout_seconds": int(snapshot_payload.get("max_runtime_seconds",
                                                   DEFAULT_LIMITS["max_runtime_seconds"])),
        "max_bytes_read": int(snapshot_payload.get("max_bytes_read",
                                                  DEFAULT_LIMITS["max_bytes_read"])),
        "max_single_file_size": int(snapshot_payload.get("max_single_file_size",
                                                         DEFAULT_LIMITS["max_single_file_size"])),
        "max_full_hash_size": int(snapshot_payload.get("max_full_hash_size",
                                                       DEFAULT_LIMITS["max_full_hash_size"])),
        "sample_block_size": int(snapshot_payload.get("sample_block_size",
                                                     DEFAULT_LIMITS["sample_block_size"])),
        "max_sample_rows": int(snapshot_payload.get("max_sample_rows",
                                                   DEFAULT_LIMITS["max_sample_rows"])),
        "max_cpu_seconds": float(snapshot_payload.get("max_cpu_seconds", 0) or 0),
        "max_rss_mb": float(snapshot_payload.get("max_rss_mb", 0) or 0),
        "xlsx_max_rows": int(snapshot_payload.get("xlsx_max_rows", DEFAULT_LIMITS["xlsx_max_rows"])),
        "xlsx_max_entries": int(snapshot_payload.get("xlsx_max_entries",
                                                    DEFAULT_LIMITS["xlsx_max_entries"])),
        "xlsx_max_uncompressed_bytes": int(
            snapshot_payload.get("xlsx_max_uncompressed_bytes",
                                 DEFAULT_LIMITS["xlsx_max_uncompressed_bytes"])),
        "xlsx_max_shared_strings": int(
            snapshot_payload.get("xlsx_max_shared_strings",
                                 DEFAULT_LIMITS["xlsx_max_shared_strings"])),
    }


def get_or_404(db: Session, profile_id: int) -> ScanProfile:
    profile = db.get(ScanProfile, profile_id)
    if profile is None:
        raise ScanProfileError(f"扫描配置 {profile_id} 不存在")
    return profile


def default_profile(db: Session, *, name: str = "default") -> ScanProfile | None:
    """The profile used when a job is queued without one, if it exists."""
    return db.scalar(select(ScanProfile).where(ScanProfile.name == name, ScanProfile.enabled.is_(True))
                     .order_by(ScanProfile.version.desc()))


def apply_values(profile: ScanProfile, values: dict[str, Any]) -> ScanProfile:
    for key, value in values.items():
        setattr(profile, key, value)
    return profile
