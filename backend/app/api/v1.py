from __future__ import annotations

from fastapi import APIRouter

from app.api.alerts import (
    router as alerts_router,
)
from app.api.assessments import (
    router as assessments_router,
)
from app.api.assets import (
    router as assets_router,
)
from app.api.auth import (
    router as auth_router,
)
from app.api.dashboard import (
    router as dashboard_router,
)
from app.api.data_assets import SENSITIVE_RULE_BUCKETS as SENSITIVE_RULE_BUCKETS
from app.api.data_assets import _sensitive_bucket as _sensitive_bucket
from app.api.data_assets import _serialize_data_asset as _serialize_data_asset
from app.api.data_assets import data_asset_detail as data_asset_detail
from app.api.data_assets import data_assets as data_assets
from app.api.data_assets import router as data_assets_router
from app.api.data_assets import sensitive_findings as sensitive_findings
from app.api.database_connections import (
    router as database_connections_router,
)
from app.api.detections import (
    router as detections_router,
)
from app.api.engines import (
    router as engines_router,
)
from app.api.file_sources import router as file_sources_router
from app.api.files import (
    router as files_router,
)
from app.api.finding_presenter import ATTACK_MAP as ATTACK_MAP
from app.api.finding_presenter import _attack as _attack
from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.health import (
    router as health_router,
)
from app.api.incidents import (
    router as incidents_router,
)
from app.api.integrations import (
    router as integrations_router,
)
from app.api.network_scan import (
    router as network_scan_router,
)
from app.api.pcaps import (
    router as pcaps_router,
)
from app.api.policy_groups import (
    router as policy_groups_router,
)
from app.api.probes import (
    router as probes_router,
)
from app.api.reports import (
    router as reports_router,
)
from app.api.rules import (
    router as rules_router,
)
from app.api.targets import (
    router as targets_router,
)
from app.api.tasks import (
    router as tasks_router,
)
from app.api.test_data import (
    router as test_data_router,
)

router = APIRouter(prefix="/api/v1")


# Legacy asset projection and sensitive findings share a dedicated read boundary.

router.include_router(data_assets_router)
router.include_router(pcaps_router)
router.include_router(files_router)
router.include_router(assets_router)
router.include_router(incidents_router)
router.include_router(alerts_router)
router.include_router(tasks_router)
router.include_router(reports_router)
router.include_router(detections_router)
router.include_router(engines_router)
router.include_router(dashboard_router)
router.include_router(probes_router)
router.include_router(integrations_router)
router.include_router(rules_router)
router.include_router(auth_router)
router.include_router(health_router)
router.include_router(network_scan_router)
router.include_router(database_connections_router)
router.include_router(file_sources_router)
router.include_router(test_data_router)
router.include_router(policy_groups_router)
router.include_router(assessments_router)
router.include_router(targets_router)
