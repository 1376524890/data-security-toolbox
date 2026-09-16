"""Timeout- and limit-bounded regular-expression matching.

Every pattern that reaches this module is data from a rule pack, so matching is
always bounded in time, input size and number of matches. ``regex`` is preferred
because it supports a real timeout; the standard library fallback caps the input
instead and is reported as a degraded capability rather than silently trusted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

try:  # pragma: no cover - depends on the install target
    import regex as _regex

    REGEX_BACKEND = "regex"
    SUPPORTS_TIMEOUT = True
except ImportError:  # pragma: no cover - probe installs may omit the wheel
    _regex = None
    REGEX_BACKEND = "re"
    SUPPORTS_TIMEOUT = False

# Bounds. The engine reports truncation instead of quietly scanning part of a file.
MAX_TEXT_CHARS = 4 * 1024 * 1024
MAX_MATCHES_PER_RULE = 10000
DEFAULT_TIMEOUT = 0.05
MAX_PATTERN_CHARS = 10000
MAX_PATTERNS = 2000


class PatternError(ValueError):
    """The pattern is unusable; the rule is skipped and reported."""


@dataclass(slots=True)
class MatchScan:
    """Matches plus what the scan cost and had to give up."""

    intervals: list[tuple[int, int]] = field(default_factory=list)
    timeouts: list[str] = field(default_factory=list)
    truncated: bool = False

    def add(self, start: int, end: int) -> None:
        if start != end:
            self.intervals.append((start, end))


def compile_pattern(pattern: str, flags: int | None = None):
    """Compile with the strongest available backend, or raise :class:`PatternError`."""
    text = str(pattern or "")
    if not text or len(text) > MAX_PATTERN_CHARS:
        raise PatternError("pattern_empty_or_too_long")
    if _regex is not None:
        return _regex.compile(text, flags if flags is not None else _regex.I | _regex.M | _regex.S)
    try:
        return re.compile(text, flags if flags is not None else re.I | re.M | re.S)
    except re.error as exc:  # pragma: no cover - defensive
        raise PatternError(str(exc)) from exc


def matches(pattern: str, text: str, timeout: float = DEFAULT_TIMEOUT, limit: int = MAX_MATCHES_PER_RULE) -> MatchScan:
    """All match intervals for one pattern, bounded in time and count."""
    scan = MatchScan()
    if not text:
        return scan
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]
        scan.truncated = True
    try:
        compiled = compile_pattern(pattern)
    except PatternError:
        raise
    if _regex is not None:
        try:
            iterator = compiled.finditer(text, timeout=timeout)
            for index, match in enumerate(iterator):
                if index >= limit:
                    scan.truncated = True
                    break
                scan.add(match.start(), match.end())
        except TimeoutError:
            scan.timeouts.append(str(pattern)[:64])
        return scan
    try:
        for index, match in enumerate(compiled.finditer(text)):
            if index >= limit:
                scan.truncated = True
                break
            scan.add(match.start(), match.end())
    except re.error:  # pragma: no cover - defensive
        scan.timeouts.append(str(pattern)[:64])
    return scan


def first_match(pattern: str, text: str, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Cheap compiled-probe used when validating a rule (must not match "")."""
    if not text:
        return False
    try:
        compiled = compile_pattern(pattern)
    except PatternError:
        return False
    if _regex is not None:
        try:
            return compiled.search(text, timeout=timeout) is not None
        except TimeoutError:
            return False
    return compiled.search(text) is not None


def matches_empty(pattern: str, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """True when a pattern matches the empty string.

    Such a pattern can only add noise to a report, so a rule that declares one is
    rejected at registration time rather than being matched against every file.
    """
    try:
        compiled = compile_pattern(pattern)
    except PatternError:
        raise
    if _regex is not None:
        try:
            return compiled.search("", timeout=timeout) is not None
        except TimeoutError:
            return False
    return compiled.search("") is not None


def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Union of overlapping/adjacent spans.

    Two recognizers matching the same characters are one finding: counts must not
    grow just because a value was seen twice.
    """
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged = [list(ordered[0])]
    for start, end in ordered[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]
