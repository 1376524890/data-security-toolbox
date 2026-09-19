"""Keep the incident/indicator HTTP boundary out of the aggregate router.

The split this guards: ``app.api.incidents`` declares the incident triage and
IOC association routes, while correlation stays in ``incident_engine``, the row
shapes come from the shared presenters, and the list time filter lives once in
``app.api.query_filters``.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
V1 = APP / "api" / "v1.py"
INCIDENTS = APP / "api" / "incidents.py"
FILTERS = APP / "api" / "query_filters.py"

#: Frozen incident/IOC surface: the split must not add, drop or rename one entry.
INCIDENT_ROUTES = {
    ("GET", "/incidents"),
    ("GET", "/incidents/{incident_id}"),
    ("PATCH", "/incidents/{incident_id}"),
    ("POST", "/incidents/correlate"),
    ("POST", "/incidents/rebuild-attribution"),
    ("GET", "/iocs"),
    ("GET", "/iocs/{ioc_id}/associations"),
}

#: HTTP methods a route may be declared with.
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
PREFIXES = ("/incidents", "/iocs")


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


def test_incident_routes_are_declared_by_the_incident_module_only():
    assert router_routes(INCIDENTS) == INCIDENT_ROUTES
    leftover = {route for route in router_routes(V1) if route[1].startswith(PREFIXES)}
    assert leftover == set()


def test_incident_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in INCIDENT_ROUTES} <= mounted


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


def test_incident_domain_does_not_reach_into_workers_or_extensions():
    for module in (
        node.module or ""
        for node in ast.walk(ast.parse(INCIDENTS.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
    ):
        assert not module.startswith(("app.workers", "app.api.extensions")), module


def test_incident_domain_reuses_the_shared_presenters_instead_of_copying_them():
    source = INCIDENTS.read_text(encoding="utf-8")
    for shared in (
        "from app.api.finding_presenter import",
        "from app.api.incident_presenter import serialize_incident",
        "from app.api.ioc_presenter import serialize_ioc",
        "from app.api.assets import serialize_asset",
        "from app.api.query_filters import",
    ):
        assert shared in source, shared
    for redefined in (
        "def _serialize_detection(",
        "def serialize_incident(",
        "def serialize_ioc(",
        "def serialize_asset(",
        "def string_time_filter(",
    ):
        assert redefined not in source, redefined


def test_incident_engine_correlation_is_not_reimplemented_in_the_route():
    source = INCIDENTS.read_text(encoding="utf-8")
    assert "from app.incident_engine.engine import IncidentEngine" in source
    assert "def correlate(" not in source
    assert "def _correlation_keys(" not in source


def test_the_list_time_filter_has_a_single_implementation():
    assert "def string_time_filter(" in FILTERS.read_text(encoding="utf-8")
    moved = V1.read_text(encoding="utf-8")
    assert "def _string_time_filter(" not in moved
    assert "def string_time_filter(" not in moved


def test_v1_aggregates_the_incident_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(incidents_router)") == 1
