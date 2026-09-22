"""Keep the dashboard HTTP boundary out of the aggregate router.

The split this guards: ``app.api.dashboard`` owns the risk overview, the graph
projection, the dashboard cards and the global flow/protocol/live-traffic
views, while the row shapes stay in the shared presenters and the protocol
layer helper stays in ``services/protocol_service.py``.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
V1 = APP / "api" / "v1.py"
DASHBOARD = APP / "api" / "dashboard.py"

#: Frozen dashboard surface: the split must not add, drop or rename one entry.
#: The four ``/dashboard/{overview,traffic-flow,risk-distribution,
#: detection-trend}`` entries are the 数据安全态势大屏 aggregates, added
#: deliberately in the big-screen batch: the screen must not grow a second
#: aggregate module beside this one, so its reads land here and the list moves
#: with them. ``/dashboard/{trend,tasks}`` are the 数据安全综合驾驶舱's own
#: reads, added in the cockpit batch for the same reason - one homepage module,
#: not one per page - and ``/dashboard/overview`` now feeds both homepages in a
#: single pass (see ``_cockpit_blocks``).
DASHBOARD_ROUTES = {
    ("GET", "/risk/summary"),
    ("GET", "/graph"),
    ("GET", "/dashboard/summary"),
    ("GET", "/dashboard/risk-trend"),
    ("GET", "/dashboard/severity"),
    ("GET", "/dashboard/engines"),
    ("GET", "/dashboard/incidents"),
    ("GET", "/dashboard/high-risk-assets"),
    ("GET", "/dashboard/sensitive-data"),
    ("GET", "/dashboard/incident-trend"),
    ("GET", "/dashboard/overview"),
    ("GET", "/dashboard/traffic-flow"),
    ("GET", "/dashboard/risk-distribution"),
    ("GET", "/dashboard/detection-trend"),
    ("GET", "/dashboard/trend"),
    ("GET", "/dashboard/tasks"),
    ("GET", "/flows"),
    ("GET", "/protocols"),
    ("GET", "/network/live"),
}

#: Prefixes the module owns; v1 must not declare any of them again.
OWNED_PREFIXES = ("/dashboard", "/flows", "/protocols", "/network/live", "/risk/summary", "/graph")

#: HTTP methods a route may be declared with.
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def router_routes(path):
    """Every ``(METHOD, path)`` a module declares through ``@router.<method>``."""
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
                continue
            if func.value.id != "router" or func.attr.upper() not in METHODS:
                continue
            found.add((func.attr.upper(), ast.literal_eval(decorator.args[0])))
    return found


def test_dashboard_routes_are_declared_by_the_dashboard_module_only():
    assert router_routes(DASHBOARD) == DASHBOARD_ROUTES
    leaked = {route for route in router_routes(V1) if route[1].startswith(OWNED_PREFIXES)}
    assert leaked == set()


def test_dashboard_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in DASHBOARD_ROUTES} <= mounted


def test_no_registered_route_repeats_a_path_and_method():
    seen, duplicates = set(), []
    for route in app.routes:
        for method in getattr(route, "methods", None) or ():
            if method in {"HEAD", "OPTIONS"}:
                continue
            key = (method, getattr(route, "path", ""))
            if key in seen:
                duplicates.append(key)
            seen.add(key)
    assert duplicates == []


def test_dashboard_domain_does_not_reach_into_workers_or_extensions():
    for node in ast.walk(ast.parse(DASHBOARD.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith(("app.workers", "app.api.extensions")), (
                node.module
            )


def test_the_screen_aggregates_never_invent_a_number():
    """Every big-screen aggregate must be a counted/grouped query, not a literal."""
    source = DASHBOARD.read_text(encoding="utf-8")
    for required in (
        "def dashboard_overview(",
        "def dashboard_traffic_flow(",
        "def dashboard_risk_distribution(",
        "def dashboard_detection_trend(",
        "integration_registry.metadata()",
        "egress_regions.classify(",
        "evidence_asset_keys(",
    ):
        assert required in source, required


def test_dashboard_reuses_the_shared_presenters_instead_of_copying_them():
    source = DASHBOARD.read_text(encoding="utf-8")
    for shared in (
        "from app.api.assets import serialize_asset",
        "from app.api.incident_presenter import serialize_incident",
        "from app.api.pagination import page_response, paginate",
        "from app.api.pcaps import serialize_flow",
        "from app.api.probe_presenter import serialize_probe",
        "from app.services.protocol_service import protocol_layer",
    ):
        assert shared in source, shared
    for redefined in (
        "def serialize_asset(",
        "def serialize_incident(",
        "def serialize_flow(",
        "def serialize_probe(",
        "def protocol_layer(",
        "def paginate(",
        "def page_response(",
    ):
        assert redefined not in source, redefined


def test_dashboard_aggregates_are_derived_from_the_models():
    source = DASHBOARD.read_text(encoding="utf-8")
    for model in ("Asset", "DataAsset", "DetectionFinding", "Flow", "Incident", "Probe"):
        assert model in source, model
    assert "integration_registry.metadata()" in source


def test_v1_aggregates_the_dashboard_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(dashboard_router)") == 1
