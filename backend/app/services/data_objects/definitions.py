"""Stable data-object vocabulary and compatibility constants."""

from __future__ import annotations

import re

HASH_FULL = "full_sha256"


HASH_PARTIAL = "partial_fingerprint"


HASH_SCOPED = "scoped"


IDENTITY_FULL = 1.0


IDENTITY_PARTIAL = 0.5


IDENTITY_SCOPED = 0.0


INSTANCE_ACTIVE = "ACTIVE"


INSTANCE_NOT_OBSERVED = "NOT_OBSERVED"


INSTANCE_RESERVED = ("STALE", "DISAPPEARED")


SCOPED_KEY_SALT = "dst-object-v1"


MAX_SUMMARY_ROWS = 50_000


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


_HEX_DIGEST = re.compile(r"^[0-9a-f]{32,64}$")


REPORT_SCHEMA_SUPPORTED = ("1.0", "1.1")


class DataObjectError(ValueError):
    """Raised for a payload the ingestion refuses to interpret."""


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
