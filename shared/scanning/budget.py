"""One budget for every byte a scan may spend.

Hash, magic probe, sampling, decompression and parsing all draw from the same
counters, so a scan cannot exceed its limits by moving work from one stage to
another. The budget is deliberately conservative about what it claims: process
CPU time and RSS are *throttle/abort signals*, not OS-enforced isolation - a
plain Python thread cannot deliver that, and reporting it as if it could would
be a false capability claim.

Time is monotonic, counters are updated in one place, and every check is
chunk-sized so a long read can be interrupted between chunks.
"""
from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Any

# Why a scan stopped early. "complete" is the only value that permits marking
# unseen instances as NOT_OBSERVED on the platform.
TERMINATION_COMPLETE = "complete"
TERMINATION_TIMEOUT = "timeout"
TERMINATION_CANCELLED = "cancelled"
TERMINATION_FILES = "file_budget"
TERMINATION_DIRECTORIES = "directory_budget"
TERMINATION_BYTES = "byte_budget"
TERMINATION_FILE_SIZE = "single_file_limit"
TERMINATION_ROWS = "row_budget"
TERMINATION_TREE = "depth_or_exclude"
TERMINATION_RESOURCES = "resource_limit"
TERMINATION_UNREADABLE = "unreadable"
#: Nothing was configured to scan; this is not a completed scope either.
TERMINATION_UNCONFIGURED = "unconfigured"

#: Reasons that only say one file's *content* was sampled incompletely. The file
#: itself was still listed, so the walk must keep going: a single long file used
#: to end the whole inventory (one /var/backups dump stopped the /var scan).
#: They still make the report incomplete, so nothing unseen gets retired.
CONTENT_TRUNCATION_REASONS = frozenset({TERMINATION_ROWS, TERMINATION_FILE_SIZE})

# One rule for every *coverage* knob - files, directories, depth, bytes, and
# wall-clock: **0 means "no limit"**, so an operator can ask a scan to cover a
# whole tree instead of stopping early. A non-zero value is their own cap and is
# clamped to the matching ceiling. Ceilings apply to non-zero values only, so
# they can never turn "unlimited" into a silent floor (a floor of 1 second is
# exactly how every file-source check task used to end "Partial / time_budget").
# Content knobs (row sampling, XLSX limits, block size) keep their shipped
# defaults: they bound how much of *one* file is parsed for detection, not which
# files the scan reaches.
DEFAULT_LIMITS: dict[str, Any] = {
    "max_files": 0,
    "max_files_ceiling": 100000,
    "max_depth": 0,
    "max_depth_ceiling": 64,
    "max_dirs": 0,
    #: 0 means "no time limit": the run is bounded by bytes/files instead.
    "max_runtime_seconds": 0,
    "max_runtime_ceiling": 0,
    "max_bytes_read": 0,
    "max_single_file_size": 0,
    "max_full_hash_size": 0,
    "large_file_sampling": True,
    "sample_block_size": 64 * 1024,
    "max_sample_rows": 25,
    "max_cpu_seconds": 0.0,
    "max_rss_mb": 0.0,
    # XLSX is the one container format that is parsed rather than merely listed.
    "xlsx_max_entries": 512,
    "xlsx_max_uncompressed_bytes": 64 * 1024 * 1024,
    "xlsx_max_compression_ratio": 200.0,
    "xlsx_max_shared_strings": 200_000,
    "xlsx_max_sheets": 32,
    "xlsx_max_columns": 256,
    "xlsx_max_rows": 200,
}


def _capped(value: Any, ceiling: Any) -> int:
    """A limit with one meaning for 0: unlimited.

    Non-zero values are clamped to ``ceiling`` when one is configured, so a typo
    cannot ask for more than the ceiling allows - but 0 never becomes a silent
    floor, which is what made "0 = no time limit" behave like a one-second run.
    """
    limit = int(value or 0)
    if limit <= 0:
        return 0
    return min(limit, int(ceiling)) if ceiling else limit


class BudgetExceeded(RuntimeError):
    """The scan must stop; ``reason`` says which limit was reached."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass
class ScanBudget:
    """Shared, chunk-checked counters for one scan task."""

    limits: dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=time.monotonic)
    files: int = 0
    directories: int = 0
    bytes_read: int = 0
    rows: int = 0
    sensitive_assets: int = 0
    detections: int = 0
    skipped: int = 0
    truncated_files: list[str] = field(default_factory=list)
    #: Last path the walker touched; reported with progress so a stalled scan is
    #: visibly stalled instead of just slow.
    current_path: str = ""
    #: Enumeration and content sampling are tracked apart: a file whose content
    #: was sampled past the row limit says nothing about whether the rest of the
    #: tree was listed, so it must not end the walk.
    _enumeration_reason: str = ""
    _enumeration_detail: str = ""
    _content_reason: str = ""
    _content_detail: str = ""
    _stop_event: Any = None

    def __post_init__(self) -> None:
        merged = dict(DEFAULT_LIMITS)
        merged.update({key: value for key, value in (self.limits or {}).items() if value is not None})
        self.limits = merged
        # 0 = unlimited for each coverage knob; only a non-zero value is clamped.
        self.max_files = _capped(merged["max_files"], merged["max_files_ceiling"])
        self.max_depth = _capped(merged["max_depth"], merged["max_depth_ceiling"])
        self.max_dirs = _capped(merged["max_dirs"], None)
        # 0 means "no time limit". A requested cap is honoured and only clamped
        # when a ceiling is actually configured - the old rule dropped every
        # requested timeout whenever the ceiling was 0, so a profile asking for a
        # 120 s budget silently ran unbounded instead.
        runtime = float(merged["max_runtime_seconds"] or 0)
        ceiling = float(merged.get("max_runtime_ceiling") or 0)
        if runtime <= 0:
            self.max_runtime = 0.0
        else:
            self.max_runtime = min(runtime, ceiling) if ceiling > 0 else runtime
        self.max_bytes = _capped(merged["max_bytes_read"], None)
        self.max_single_file = _capped(merged["max_single_file_size"], None)
        self.max_full_hash = _capped(merged["max_full_hash_size"], None)
        self.block_size = max(int(merged["sample_block_size"]), 1024)
        self.max_rows = max(int(merged["max_sample_rows"]), 1)
        self.max_cpu = max(float(merged.get("max_cpu_seconds") or 0), 0.0)
        self.max_rss_mb = max(float(merged.get("max_rss_mb") or 0), 0.0)
        self.deadline = self.started_at + self.max_runtime if self.max_runtime else None

    # -- limits -------------------------------------------------------------
    def limit(self, name: str, fallback: Any = 0) -> Any:
        return self.limits.get(name, fallback)

    def clamp_file_size(self, size: int) -> int:
        """Bytes this file may contribute, capped by the per-file sample limit.

        With no per-file limit configured the whole file is in scope, so the
        caller can read it end to end instead of sampling windows.
        """
        if not self.max_single_file:
            return max(int(size), 0)
        return min(max(int(size), 0), self.max_single_file)

    # -- cooperative stop ---------------------------------------------------
    def attach_stop_event(self, stop_event: Any) -> None:
        self._stop_event = stop_event

    def cancelled(self) -> bool:
        return bool(self._stop_event is not None and self._stop_event.is_set())

    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def remaining_seconds(self) -> float:
        if self.deadline is None:
            return float("inf")
        return max(self.deadline - time.monotonic(), 0.0)

    def check(self) -> None:
        """Abort when the scan has run out of budget. Called between chunks.

        The reason is recorded *before* raising. A scan that stops early must never
        be left looking complete: ``complete_scope`` is what allows the platform to
        mark instances in this scope as NOT_OBSERVED, so an aborted scan that still
        reported "complete" would let a timeout silently declare live data gone.
        """
        if self.cancelled():
            self.stop(TERMINATION_CANCELLED, "stop requested")
            raise BudgetExceeded(TERMINATION_CANCELLED, "stop requested")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.stop(TERMINATION_TIMEOUT, f"{self.max_runtime:.0f}s")
            raise BudgetExceeded(TERMINATION_TIMEOUT, f"{self.max_runtime:.0f}s")
        # 0 = no byte ceiling; only an explicit cap can stop the read.
        if self.max_bytes and self.bytes_read >= self.max_bytes:
            self.stop(TERMINATION_BYTES, f"{self.max_bytes} bytes")
            raise BudgetExceeded(TERMINATION_BYTES, f"{self.max_bytes} bytes")
        if self.max_cpu and time.process_time() - self.started_at > self.max_cpu:
            # A soft limit: we stop the scan, we do not claim to have cgrouped it.
            self.stop(TERMINATION_RESOURCES, f"cpu {self.max_cpu}s")
            raise BudgetExceeded(TERMINATION_RESOURCES, f"cpu {self.max_cpu}s")
        if self.max_rss_mb:
            rss = self._rss_mb()
            if rss and rss > self.max_rss_mb:
                self.stop(TERMINATION_RESOURCES, f"rss {rss:.0f}MB")
                raise BudgetExceeded(TERMINATION_RESOURCES, f"rss {rss:.0f}MB")

    @staticmethod
    def _rss_mb() -> float:
        try:  # psutil is optional on a probe install
            import psutil

            return float(psutil.Process().memory_info().rss) / (1024 * 1024)
        except Exception:
            try:
                with open("/proc/self/statm", "r", encoding="ascii") as handle:
                    pages = int(handle.read().split()[1])
                return pages * 4096 / (1024 * 1024)
            except Exception:
                return 0.0

    # -- accounting ---------------------------------------------------------
    def remaining_bytes(self) -> int:
        # Unlimited reads report the whole address space so ``clamp_read`` never
        # becomes the thing that truncates a file.
        if not self.max_bytes:
            return sys.maxsize
        return max(self.max_bytes - self.bytes_read, 0)

    def clamp_read(self, requested: int) -> int:
        """Largest read that still fits the byte budget.

        Parsers clamp every region read through this, so a single "read the head"
        call cannot overshoot the budget it was given. Zero means: stop reading.
        """
        return max(min(int(requested), self.remaining_bytes()), 0)

    def spend_bytes(self, count: int) -> None:
        self.bytes_read += max(int(count), 0)

    def spend_rows(self, count: int) -> None:
        self.rows += max(int(count), 0)
        if self.max_rows and self.rows > self.max_rows * 64:
            self.stop(TERMINATION_ROWS, f"{self.rows} rows")

    def note_file(self) -> None:
        self.files += 1
        if self.max_files and self.files > self.max_files:
            self.stop(TERMINATION_FILES, f"{self.max_files} files")
            raise BudgetExceeded(TERMINATION_FILES, f"{self.max_files} files")

    def note_directory(self) -> None:
        self.directories += 1
        if self.max_dirs and self.directories > self.max_dirs:
            self.stop(TERMINATION_DIRECTORIES, f"{self.max_dirs} directories")
            raise BudgetExceeded(TERMINATION_DIRECTORIES, f"{self.max_dirs} directories")

    def note_skip(self) -> None:
        self.skipped += 1

    def stop(self, reason: str, detail: str = "") -> None:
        """Record the first reason the scan did not finish completely.

        The first reason of each kind is kept, so a later, coarser limit cannot
        overwrite the specific one an operator needs.
        """
        if reason == TERMINATION_COMPLETE:
            return
        if reason in CONTENT_TRUNCATION_REASONS:
            if not self._content_reason:
                self._content_reason, self._content_detail = reason, detail
        elif not self._enumeration_reason:
            self._enumeration_reason, self._enumeration_detail = reason, detail

    def mark_truncated(self, name: str) -> None:
        # No cap: the list is what tells an operator which files were only
        # sampled, and a truncated list of truncated files is not a report.
        if name not in self.truncated_files:
            self.truncated_files.append(name)

    # -- reporting ----------------------------------------------------------
    @property
    def termination_reason(self) -> str:
        """Why the scope is not fully covered; an enumeration stop is named first.

        A walk that ended early is the stronger statement: it is the one that
        decides what was never looked at, so it outranks content truncation.
        """
        if self._enumeration_reason:
            return self._enumeration_reason
        return self._content_reason or TERMINATION_COMPLETE

    @property
    def termination_detail(self) -> str:
        if self._enumeration_reason:
            return self._enumeration_detail
        return self._content_detail

    @property
    def complete(self) -> bool:
        """True only when the walk finished *and* every file was read in full."""
        return not self._enumeration_reason and not self._content_reason

    @property
    def enumeration_complete(self) -> bool:
        """True when the walk reached the end of the configured scope."""
        return not self._enumeration_reason

    @property
    def content_complete(self) -> bool:
        """True when every listed file was read within the content limits."""
        return not self._content_reason

    def coverage(self) -> dict[str, Any]:
        return {
            # `max_files` is the only total either side knows without a second walk;
            # it is published as the denominator an honest estimate needs.
            "max_files": self.max_files,
            "files_discovered": self.files + self.skipped,
            "files_analyzed": self.files,
            "files_skipped": self.skipped,
            "directories_scanned": self.directories,
            "bytes_read": self.bytes_read,
            "rows_read": self.rows,
            "sensitive_assets": self.sensitive_assets,
            "detections": self.detections,
            "elapsed_seconds": round(self.elapsed(), 3),
            "complete_scope": self.complete,
            # Two honest answers instead of one ambiguous one: the tree may be
            # fully listed while individual files were only partly read.
            "enumeration_complete": self.enumeration_complete,
            "content_complete": self.content_complete,
            "termination_reason": self.termination_reason,
            "termination_detail": self.termination_detail,
            "truncated_files": list(self.truncated_files),
            "current_path": self.current_path,
        }
