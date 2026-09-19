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
    line_truncated: bool = False
    #: The file ended without a newline; the final line is kept (it is real data)
    #: but may be an incomplete record, so it is flagged rather than dropped.
    last_line_unterminated: bool = False

    def defused(self) -> str:
        return self.text


def decode(raw: bytes) -> str:
    for encoding in ENCODINGS:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _align_to_line(raw: bytes, *, keep_leading_partial: bool, at_eof: bool) -> bytes:
    """Trim a sample to whole lines unless it already starts at the file head.

    A region that ends at EOF keeps its final line even without a trailing
    newline: that line is complete data, and dropping it is how the last record
    of a file used to disappear from the sample.
    """
    if not keep_leading_partial:
        index = raw.find(b"\n")
        if index != -1:
            raw = raw[index + 1:]
    # Drop the trailing partial line so a half-written record is never presented
    # as a complete one - unless this read actually reached the end of the file.
    if not at_eof:
        index = raw.rfind(b"\n")
        if index != -1:
            raw = raw[: index + 1]
    return raw


def _bounded_lines(text: str) -> tuple[str, bool]:
    clipped = False
    lines = []
    for line in text.splitlines():
        if len(line) > MAX_LINE_CHARS:
            clipped = True
            line = line[:MAX_LINE_CHARS]
        lines.append(line)
    return "\n".join(lines), clipped


def _merged_ranges(positions: list[int], limit: int, size: int) -> list[tuple[int, int]]:
    """Merge overlapping/adjacent windows so no byte is read (and counted) twice."""
    ranges: list[tuple[int, int]] = []
    for offset in positions:
        start, end = offset, min(offset + limit, size)
        if ranges and start <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
        else:
            ranges.append((start, end))
    return ranges


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
    ranges = _merged_ranges(positions, limit, size)
    chunks: list[str] = []
    covered = 0
    try:
        with path.open("rb") as handle:
            for start, end in ranges:
                # Clamped to what is left of the byte budget: one "read the head"
                # call must not be able to overshoot the limit it was given.
                allowed = budget.clamp_read(end - start)
                if allowed <= 0:
                    budget.check()
                    result.termination_reason = "byte_budget"
                    result.coverage = "partial"
                    result.warning = f"字节预算 {budget.max_bytes} 已用尽"
                    break
                budget.check()
                handle.seek(start)
                raw = handle.read(allowed)
                budget.spend_bytes(len(raw))
                result.bytes_read += len(raw)
                covered += len(raw)
                result.positions.append(start)
                if raw and start + len(raw) >= size and not raw.endswith(b"\n"):
                    result.last_line_unterminated = True
                aligned = _align_to_line(raw, keep_leading_partial=start == 0,
                                         at_eof=start + len(raw) >= size)
                if aligned:
                    bounded, clipped = _bounded_lines(decode(aligned))
                    if clipped:
                        result.line_truncated = True
                    chunks.append(bounded)
    except BudgetExceeded as exc:
        result.termination_reason = exc.reason
        result.coverage = "partial"
        result.warning = exc.detail
    except OSError as exc:
        result.termination_reason = "unreadable"
        result.warning = type(exc).__name__
    result.text = "\n".join(chunks)
    if result.line_truncated:
        result.coverage = "partial"
        result.termination_reason = "line_truncated"
        result.warning = result.warning or f"单行超过 {MAX_LINE_CHARS} 字符被截断"
    elif result.termination_reason == "complete":
        # Coverage is the union of the byte ranges actually read, not the sum of
        # every read: overlapping windows used to inflate bytes_read past the
        # file size and claim a completeness that was never achieved.
        result.coverage = "complete" if covered >= size else "partial"
        if result.coverage == "partial":
            result.termination_reason = "sampled"
    return result
