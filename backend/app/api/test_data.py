# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Manual test pack: import, clear and status for the labelled demo data.

The pack is an operator opt-in behind ``settings.test_data_import_enabled`` and
never a delivery feature, so both write paths go through
``_require_test_data_import``.  The import/clear/status implementation stays in
``services/test_service.py``; this module owns paths, the opt-in guard and
response shapes only.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.services.test_service import clear_test_data, import_test_data, test_status

router = APIRouter()


def _require_test_data_import() -> None:
    """The manual test pack is an operator opt-in, never a delivery feature."""
    if not settings.test_data_import_enabled:
        raise HTTPException(403, "test data import is disabled")


@router.post("/test/import")
def import_test(
    payload: dict[str, Any] | None = None, db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Import the manual test pack (labeled test data) for demos/verification."""
    _require_test_data_import()
    return import_test_data(db)


@router.post("/test/clear")
def clear_test(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Remove all imported test data (test-demo probe + linked records)."""
    _require_test_data_import()
    return clear_test_data(db)


@router.get("/test/status")
def get_test_status(db: Session = Depends(get_db)) -> dict[str, Any]:
    return test_status(db)
