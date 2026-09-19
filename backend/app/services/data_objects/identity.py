"""File identity and scope keys, without storage access."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.services.data_objects.definitions import (
    _HEX64,
    _HEX_DIGEST,
    HASH_FULL,
    HASH_PARTIAL,
    HASH_SCOPED,
    IDENTITY_FULL,
    IDENTITY_PARTIAL,
    IDENTITY_SCOPED,
    SCOPED_KEY_SALT,
)
from app.services.data_objects.values import _text


def normalise_path(path: Any) -> str:
    """Absolute, collapsed path. Never resolved through symlinks: a symlink is a
    different instance from its target, and the probe already refuses to follow
    them."""
    text = str(path or "").strip()
    if not text:
        return ""
    if not text.startswith("/"):
        # Not a filesystem path (e.g. a `host:port` database service); keep it as
        # an opaque, stable identifier instead of pretending it is absolute.
        return text[:1024]
    parts: list[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def instance_type_for(entry: dict[str, Any], *, from_databases: bool) -> str:
    if from_databases:
        return "database_service"
    if str(entry.get("asset_type") or "") == "directory":
        return "directory"
    return "file"


def object_type_for(entry: dict[str, Any], instance_type: str) -> str:
    asset_type = str(entry.get("asset_type") or "").strip()
    if instance_type == "directory":
        return "directory"
    if instance_type == "database_service":
        return "database"
    return asset_type or "file"


def resolve_identity(
    entry: dict[str, Any], *, probe_id: int, object_type: str, path: str
) -> dict[str, Any]:
    """The object key plus the identity evidence behind it.

    A fabricated hash is never produced: with no digest the key is explicitly
    scope-local, which is what keeps two unrelated files from silently becoming
    one object.
    """
    full = _text(entry.get("sha256"), 128).strip().lower()
    if _HEX64.match(full):
        return {
            "object_key": f"full:{object_type}:{full}",
            "hash_type": HASH_FULL,
            "content_hash": full,
            "identity_confidence": IDENTITY_FULL,
            "partial_version": "",
            "partial_layout": {},
        }
    fingerprint = entry.get("evidence") if isinstance(entry.get("evidence"), dict) else {}
    fingerprint = (
        fingerprint.get("fingerprint") if isinstance(fingerprint.get("fingerprint"), dict) else {}
    )
    value = _text(fingerprint.get("value"), 128).strip().lower()
    if value and not fingerprint.get("is_full") and _HEX_DIGEST.match(value):
        version = _text(fingerprint.get("version"), 32)
        return {
            "object_key": f"partial:{version}:{value}",
            "hash_type": HASH_PARTIAL,
            "content_hash": "",
            "identity_confidence": IDENTITY_PARTIAL,
            "partial_version": version,
            "partial_layout": {
                key: fingerprint.get(key)
                for key in ("algorithm", "size", "blocks", "positions")
                if fingerprint.get(key) is not None
            },
        }
    digest = hashlib.sha256(f"{SCOPED_KEY_SALT}:{probe_id}:{path}".encode()).hexdigest()
    return {
        "object_key": f"scoped:{probe_id}:{digest[:40]}",
        "hash_type": HASH_SCOPED,
        "content_hash": "",
        "identity_confidence": IDENTITY_SCOPED,
        "partial_version": "",
        "partial_layout": {},
    }


def scope_key_for(payload: dict[str, Any], *, probe_id: int) -> str:
    """A scope is only comparable to itself: roots, depth, profile and probe."""
    roots = sorted(
        {normalise_path(item) for item in (payload.get("scanned_paths") or []) if str(item).strip()}
    )
    blob = json.dumps(
        {
            "probe": probe_id,
            "roots": roots,
            "depth": payload.get("max_depth"),
            "profile": _text(payload.get("profile_version"), 64),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:48]
