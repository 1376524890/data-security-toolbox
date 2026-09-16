"""Server-side data-asset report validation, backed by the shared guard.

The probe sanitises every report before it leaves the host; this module is the
independent check on the receiving side so a report is never trusted merely
because the sender claims it is clean.

Scope: data-asset reports only. Probe authentication headers, login payloads and
other business bodies keep their existing validation and are deliberately not run
through these rules, so a legitimate ``token``/``password`` field elsewhere is
never rejected.
"""
from __future__ import annotations

from app.services.sensitive_engine import SHARED_ROOT  # noqa: F401  (bootstraps sys.path)

from shared.sensitive_detection.report_guard import (  # noqa: E402
    SanitizeAudit,
    Violation,
    sanitize_report,
    validate_report,
)

__all__ = ["SHARED_ROOT", "SanitizeAudit", "Violation", "sanitize_report", "validate_report"]
