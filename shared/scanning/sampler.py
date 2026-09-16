"""Bounded multi-position sampling for plain text and log files.

A large log is not "the head plus a note": sensitive values cluster wherever the
data is, so several positions are read and each is aligned to a line boundary
without dropping the first or last (possibly partial) line. Every read is
clamped to the file size and charged to the budget, and the result records how
much of the file it actually saw.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .budget import BudgetExceeded

CHUNK = 64 * 1024
#: Fractional positions sampled, in the same order as the fingerprint layout.
POSITIONS = (0.0, 0.25, 0.5, 0.75, 1.0)
ENCODINGS = ("utf-8-sig", "gb18030")

#: Longest single "line" kept from an unbroken binary-ish blob, so one enormous
#: line cannot pull a whole sample into memory as one token.
MAX_LINE_CHARS = 8192


@dataclass(slots=True)
class Sample:
    """Text handed to the engine plus what it cost. ``text`` is never reported."""

    text: str = ""
    bytes_read: int = 0
    positions: list[int] = field(default_factory=list)
    coverage: str = "partial"
    termination_reason: str = "complete"
    warning: str = ""

    def defused(self) -> str:
        return self.text


def decode(raw: bytes) -> str:
    for encoding in ENCODINGS:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _align_to_line(raw: bytes, *, keep_leading_partial: bool) -> bytes:
    """Trim a sample to whole lines unless it already starts at the file head."""
    if not keep_leading_partial:
        index = raw.find(b"\n")
        if index != -1:
            raw = raw[index + 1:]
    # Drop the trailing partial line so a half-written record is never presented
    # as a complete one.
    index = raw.rfind(b"\n")
    if index != -1:
        raw = raw[: index + 1]
    return raw


def _bounded_lines(text: str) -> str:
    return "\n".join(line[:MAX_LINE_CHARS] for line in text.splitlines())


def sample_text(path: Path, size: int, *, budget, block_size: int = CHUNK,
                whole_file_limit: int | None = None) -> Sample:
    """Read bounded samples from up to five positions of a text file."""
    limit = block_size if whole_file_limit is None else whole_file_limit
    result = Sample()
    if size <= 0:
        result.coverage = "complete"
        return result
    if size <= limit:
        positions = [0]
    else:
        positions = sorted({max(min(int(round(p * (size - limit))), size - limit), 0) for p in POSITIONS})
        if size - limit not in positions:
            positions.append(size - limit)
        positions = sorted(set(positions))
    chunks: list[str] = []
    try:
        with path.open("rb") as handle:
            for offset in positions:
                # Clamped to what is left of the byte budget: one "read the head"
                # call must not be able to overshoot the limit it was given.
                allowed = budget.clamp_read(min(limit, size - offset))
                if allowed <= 0:
                    budget.check()
                    result.termination_reason = "byte_budget"
                    result.coverage = "partial"
                    result.warning = f"字节预算 {budget.max_bytes} 已用尽"
                    break
                budget.check()
                handle.seek(offset)
                raw = handle.read(allowed)
                budget.spend_bytes(len(raw))
                result.bytes_read += len(raw)
                result.positions.append(offset)
                aligned = _align_to_line(raw, keep_leading_partial=offset == 0)
                if aligned:
                    chunks.append(_bounded_lines(decode(aligned)))
    except BudgetExceeded as exc:
        result.termination_reason = exc.reason
        result.coverage = "partial"
        result.warning = exc.detail
    except OSError as exc:
        result.termination_reason = "unreadable"
        result.warning = type(exc).__name__
    result.text = "\n".join(chunks)
    if result.termination_reason == "complete":
        result.coverage = "complete" if result.bytes_read >= size else "partial"
        if result.coverage == "partial":
            result.termination_reason = "sampled"
    return result
