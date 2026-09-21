"""Read-only data-security assessment endpoints.

Six GET routes, one per tab plus the overview. Every response is the same
five-段式 envelope (结论条 → KPI 带分母 → 主视图 → 明细 → 口径与缺口) and is
computed on the fly from the existing object model and engines; nothing here
writes a row or caches a number.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.assessments import classification, compliance, egress, exposure, flow, overview

router = APIRouter(tags=["assessments"])


@router.get("/assessments/overview")
def assessment_overview(db: Session = Depends(get_db)) -> dict:
    return overview.build(db)


@router.get("/assessments/classification")
def assessment_classification(db: Session = Depends(get_db)) -> dict:
    return classification.build(db)


@router.get("/assessments/exposure")
def assessment_exposure(db: Session = Depends(get_db)) -> dict:
    return exposure.build(db)


@router.get("/assessments/flow")
def assessment_flow(db: Session = Depends(get_db)) -> dict:
    return flow.build(db)


@router.get("/assessments/egress")
def assessment_egress(db: Session = Depends(get_db)) -> dict:
    return egress.build(db)


@router.get("/assessments/compliance")
def assessment_compliance(db: Session = Depends(get_db)) -> dict:
    return compliance.build(db)
