"""File identity: full SHA256 for small files, a versioned partial fingerprint for large ones.

The two are never conflated. A partial fingerprint may only ever produce a
*marked candidate* copy ("suspected duplicate"); only a full SHA256 may claim
byte-identical content. Every offset is clamped to the real file size and
overlapping sample blocks are de-duplicated so the same bytes are not read (or
counted) twice.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .budget import BudgetExceeded

FULL_SHA256 = "FULL_SHA256"
PARTIAL_FINGERPRINT = "PARTIAL_FINGERPRINT"
#: Bumped whenever the sampling layout or the digest input changes; stored with
#: every fingerprint so an old fingerprint is never compared with a new one.
PARTIAL_VERSION = "1.0.0"
DEFAULT_BLOCK_SIZE = 64 * 1024
CHUNK = 1024 * 1024

#: Positions sampled in a large file: head, then the 25/50/75 % marks, then tail.
SAMPLE_POSITIONS = (0.0, 0.25, 0.5, 0.75, 1.0)


@dataclass(slots=True)
class Fingerprint:
    """What was computed, and what it is allowed to be used for."""

    hash_type: str = ""
    value: str = ""
    algorithm: str = ""
    version: str = ""
    file_size: int = 0
    block_size: int = 0
    blocks: list[dict[str, int]] = field(default_factory=list)
    bytes_read: int = 0
    stable: bool = True
    reason: str = ""

    @property
    def is_full(self) -> bool:
        return self.hash_type == FULL_SHA256

    def as_evidence(self) -> dict[str, Any]:
        """Safe structure metadata; deliberately carries no file content.

        The digest itself is included: a partial fingerprint is only usable as a
        *candidate* marker if the platform receives the value it must compare. It
        is a digest of sampled blocks, never the bytes that produced it, and it is
        reported next to the layout so a value can never be read as a full hash.
        """
        return {
            "hash_type": self.hash_type,
            "value": self.value,
            "is_full": self.is_full,
            "algorithm": self.algorithm,
            "version": self.version,
            "file_size": self.file_size,
            "block_size": self.block_size,
            "blocks": self.blocks,
            "bytes_read": self.bytes_read,
            "stable": self.stable,
            "reason": self.reason,
        }


def full_sha256(path: Path, size: int, *, limit: int, budget=None) -> Fingerprint:
    """Whole-file SHA256, or an empty fingerprint when the file exceeds ``limit``.

    A file whose size changes while it is being read cannot be reported as a
    confirmed full hash: the digest would describe a mixture of two versions.
    """
    if limit and size > limit:
        return Fingerprint(reason="over_full_hash_limit", file_size=size, stable=False)
    digest = hashlib.sha256()
    read = 0
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            while True:
                if budget is not None:
                    budget.check()
                chunk = handle.read(CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
                read += len(chunk)
                if budget is not None:
                    budget.spend_bytes(len(chunk))
                    # `check()` records the reason before raising; raising a bare
                    # BudgetExceeded here would leave the scan looking complete.
                    budget.check()
            after = os.fstat(handle.fileno())
    except BudgetExceeded:
        raise
    except OSError as exc:
        return Fingerprint(reason=f"unreadable:{type(exc).__name__}", file_size=size, stable=False)
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or read != before.st_size:
        return Fingerprint(algorithm="sha256", file_size=size, bytes_read=read, stable=False,
                           reason="changed_during_read")
    return Fingerprint(hash_type=FULL_SHA256, value=digest.hexdigest(), algorithm="sha256", file_size=size,
                       bytes_read=read, stable=True)


def block_layout(size: int, block_size: int = DEFAULT_BLOCK_SIZE) -> list[dict[str, int]]:
    """Non-overlapping sample blocks covering HEAD/25/50/75/TAIL of a file.

    Small files simply get one block; the layout never reads past the end and
    never asks for a negative offset.
    """
    if size <= 0:
        return []
    block = max(int(block_size), 1024)
    if size <= block:
        return [{"position": 0, "offset": 0, "length": size}]
    offsets: list[int] = []
    for position in SAMPLE_POSITIONS:
        offset = int(round(position * (size - block)))
        if position == 1.0:
            offset = size - block
        offsets.append(max(min(offset, max(size - block, 0)), 0))
    # De-duplicate overlapping positions (a small multiple of block size) and keep
    # the order stable so the digest is reproducible.
    seen: set[int] = set()
    layout: list[dict[str, int]] = []
    for index, offset in enumerate(offsets):
        if offset in seen:
            continue
        seen.add(offset)
        length = min(block, size - offset)
        layout.append({"position": index, "offset": offset, "length": length})
    return layout


def partial_fingerprint(path: Path, size: int, *, block_size: int = DEFAULT_BLOCK_SIZE,
                        budget=None) -> Fingerprint:
    """Versioned digest over a fixed, bounded sample layout of a large file."""
    layout = block_layout(size, block_size)
    if not layout:
        return Fingerprint(reason="empty_file", file_size=size, stable=False)
    digest = hashlib.sha256()
    digest.update(f"v{PARTIAL_VERSION}:{size}:{block_size}:".encode("ascii"))
    read = 0
    positions: list[dict[str, int]] = []
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            for block in layout:
                handle.seek(block["offset"])
                # A short read at the tail is real file shrinkage, not a bug.
                data = handle.read(block["length"])
                read += len(data)
                if budget is not None:
                    budget.check()
                    budget.spend_bytes(len(data))
                digest.update(block["offset"].to_bytes(8, "big"))
                digest.update(len(data).to_bytes(8, "big"))
                digest.update(data)
                positions.append({**block, "length": len(data)})
            after = os.fstat(handle.fileno())
    except BudgetExceeded:
        raise
    except OSError as exc:
        return Fingerprint(reason=f"unreadable:{type(exc).__name__}", file_size=size, stable=False)
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        return Fingerprint(algorithm="sha256", version=PARTIAL_VERSION, file_size=size,
                           block_size=block_size, blocks=positions, bytes_read=read, stable=False,
                           reason="changed_during_read")
    return Fingerprint(hash_type=PARTIAL_FINGERPRINT, value=digest.hexdigest(), algorithm="sha256",
                       version=PARTIAL_VERSION, file_size=size, block_size=block_size,
                       blocks=positions, bytes_read=read, stable=True)


def identify(path: Path, size: int, *, max_full_hash_size: int, block_size: int = DEFAULT_BLOCK_SIZE,
             budget=None) -> Fingerprint:
    """Full hash for small files, partial fingerprint for large ones."""
    if max_full_hash_size and size <= max_full_hash_size:
        return full_sha256(path, size, limit=max_full_hash_size, budget=budget)
    return partial_fingerprint(path, size, block_size=block_size, budget=budget)
