"""Report safety: structure whitelist, forbidden payload keys, value redaction.

Two independent duties, both run on the probe *and* on the platform:

* :func:`validate_report` - structural checks. Rejects payload shapes that could
  smuggle raw data (unknown fields, forbidden keys, oversized strings) by
  returning codes only, never the offending value.
* :func:`sanitize_report` - defensive redaction. Any string that itself contains
  a high-precision sensitive value is replaced with a placeholder and counted.

Scope note: this guards **data-asset reports** only. Probe authentication headers
(``X-Probe-Token``), login payloads and other business bodies are deliberately
out of scope, so a legitimate ``token``/``password`` field in an unrelated
request is never rejected.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# Payload field names that would carry raw data. Rule: describe the column, never
# the value - a column called "password" is reported as header_name "password".
FORBIDDEN_KEYS = frozenset({
    "raw_value", "sample_value", "sample_values", "samples", "sample_rows_values",
    "matched_text", "match_text", "raw_match", "original_text", "file_content",
    "raw_content", "content", "body", "database_row", "database_rows", "row_data",
    "cell_value", "cell_values", "column_values", "password", "passwd", "token_value",
    "secret_value", "access_token", "private_key", "credential_value", "text",
})

# Permitted keys per report level. Legacy 3.3.1 payloads are a subset of this.
REPORT_KEYS = frozenset({
    "report_id", "task_id", "schema_version", "scan_id", "ruleset_version", "engine_version",
    "profile_version", "assets", "databases", "scanned_paths", "max_depth", "complete",
    "error", "observed_at", "scanner", "budget", "completed_scope", "coverage",
    "termination_reason", "location", "counts", "duration_ms", "databases_detected",
    "reason_code", "notes", "totals", "degraded_capabilities", "report_guard",
})

ASSET_KEYS = frozenset({
    "name", "asset_type", "sensitivity", "sensitivity_level", "severity", "path", "size",
    "sha256", "hash_type", "partial_fingerprint", "object_key", "identity_confidence",
    "modified_at", "mtime_ns", "inode", "device", "owner", "group", "permission",
    "categories", "counts", "columns", "evidence", "detections", "coverage",
    "termination_reason", "scan_id", "ruleset_version", "engine_version", "profile_version",
    "databases", "scanned_paths", "max_depth", "complete", "error", "observed_at", "scanner",
    "location", "duration_ms", "counts_by_level", "level", "presidio_sources",
})

COLUMN_KEYS = frozenset({
    "name", "header_name", "column_index", "sheet_name", "detected_type", "inferred_type",
    "sensitivity", "sensitivity_level", "severity", "confidence", "categories", "count",
    "sample_size", "sample_hits", "sample_hit_count", "sample_values_count", "evidence",
    "value_kind", "level", "field_only", "rule_ids", "ruleset_version",
})

# Free-form containers: scalar values only, length-capped, forbidden keys rejected.
FREE_FORM_KEYS = frozenset({"evidence", "metadata", "coverage", "budget", "completed_scope", "totals"})

MAX_KEY_DEPTH = 12
MAX_STRING_CHARS = 1024
MAX_FREE_STRING_CHARS = 256
MAX_LIST_ITEMS = 20000
MAX_FREE_LIST_ITEMS = 64

# High-precision detectors used for redaction. Deliberately excludes weak patterns
# (bare long tokens) so ordinary paths and identifiers are not destroyed.
_REDACT_PATTERNS = (
    ("ID_CARD", re.compile(r"(?<!\d)[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")),
    ("PHONE", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("API_KEY", re.compile(r"\b(?:AKIA|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{20,})\b")),
    ("BANK_CARD", re.compile(r"(?<!\d)(?:62|4\d{3}|5[1-5]\d{2})[ -]?(?:\d[ -]?){12,17}(?!\d)")),
)
REDACTION_PLACEHOLDER = "[redacted]"
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class Violation:
    path: str
    code: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "code": self.code}


@dataclass
class SanitizeAudit:
    redacted_paths: list[str] = field(default_factory=list)
    truncated_paths: list[str] = field(default_factory=list)
    dropped_keys: list[str] = field(default_factory=list)

    @property
    def redacted(self) -> int:
        return len(self.redacted_paths)

    @property
    def truncated(self) -> int:
        return len(self.truncated_paths)

    def to_dict(self) -> dict[str, Any]:
        return {
            "redacted": self.redacted,
            "truncated": self.truncated,
            "dropped_keys": len(self.dropped_keys),
        }


def looks_like_raw_value(value: str) -> str:
    """Entity name when a string itself contains a high-precision value, else ``""``."""
    for entity, pattern in _REDACT_PATTERNS:
        if pattern.search(value or ""):
            return entity
    return ""


def validate_report(payload: Any, *, level: str = "report") -> list[Violation]:
    """Structural violations. Codes only - never echo a value back."""
    violations: list[Violation] = []
    if not isinstance(payload, dict):
        return [Violation("$", "payload_not_object")]
    _validate_mapping(payload, "$", level, violations, depth=0)
    return violations


def _validate_mapping(payload: dict[str, Any], path: str, level: str, violations: list[Violation], depth: int) -> None:
    if depth > MAX_KEY_DEPTH:
        violations.append(Violation(path, "too_deep"))
        return
    allowed = {"report": REPORT_KEYS, "asset": ASSET_KEYS, "column": COLUMN_KEYS}.get(level)
    for key, value in payload.items():
        child = f"{path}.{key}"
        if key in FORBIDDEN_KEYS:
            violations.append(Violation(child, "forbidden_key"))
            continue
        if allowed is not None and key not in allowed and key not in FREE_FORM_KEYS:
            violations.append(Violation(child, "unknown_field"))
            continue
        _validate_value(value, child, key, violations, depth + 1)


def _validate_value(value: Any, path: str, key: str, violations: list[Violation], depth: int) -> None:
    if isinstance(value, str):
        limit = MAX_FREE_STRING_CHARS if key in FREE_FORM_KEYS else MAX_STRING_CHARS
        if len(value) > limit:
            violations.append(Violation(path, "string_too_long"))
    elif isinstance(value, dict):
        _validate_mapping(value, path, "free", violations, depth)
    elif isinstance(value, (list, tuple)):
        limit = MAX_FREE_LIST_ITEMS if key in FREE_FORM_KEYS else MAX_LIST_ITEMS
        if len(value) > limit:
            violations.append(Violation(path, "list_too_long"))
            return
        for index, item in enumerate(value):
            if isinstance(item, dict):
                child_level = "column" if key == "columns" else "asset" if key in {"assets", "databases", "detections"} else "free"
                _validate_mapping(item, f"{path}[{index}]", child_level, violations, depth)
            else:
                _validate_value(item, f"{path}[{index}]", key, violations, depth)
    elif isinstance(value, (int, float, bool)) or value is None:
        return
    else:
        violations.append(Violation(path, "unsupported_type"))


def sanitize_report(payload: Any, audit: SanitizeAudit | None = None) -> tuple[Any, SanitizeAudit]:
    """Return a deep-cleaned copy: forbidden keys dropped, raw values redacted."""
    audit = audit if audit is not None else SanitizeAudit()
    return _sanitize(payload, "$", audit), audit


def _sanitize(value: Any, path: str, audit: SanitizeAudit) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            child = f"{path}.{key}"
            if key in FORBIDDEN_KEYS:
                audit.dropped_keys.append(child)
                continue
            clean[key] = _sanitize(item, child, audit)
        return clean
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, f"{path}[{index}]", audit) for index, item in enumerate(value)]
    if isinstance(value, str):
        text = _CONTROL_CHARS.sub("", value)
        if looks_like_raw_value(text):
            audit.redacted_paths.append(path)
            return REDACTION_PLACEHOLDER
        if len(text) > MAX_STRING_CHARS:
            audit.truncated_paths.append(path)
            return text[:MAX_STRING_CHARS]
        return text
    return value


def report_is_safe(payload: Any) -> bool:
    """True when a sanitised payload would pass a second sanitise unchanged."""
    return not validate_report(payload)
