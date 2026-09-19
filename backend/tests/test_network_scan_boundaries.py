"""Keep the active network-scan surface out of the aggregate router.

The split this guards: ``app.api.network_scan`` owns ``POST /scan`` and
``GET /scan/{task_id}``, which used to be declared in ``app/api/v1.py``.  Port
selection stays in ``services/scan_service.py``, probe-side queueing in
``services/probe_task_service.py``, the task row in ``services/task_service.py``
and the dispatch through ``api/dependencies.dispatch_task``; the domain owns the
paths and response shapes only.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
V1 = API / "v1.py"
SCAN = API / "network_scan.py"
PROFILES = API / "profiles.py"

#: Frozen scan surface: the split must not add, drop or rename one entry.
SCAN_ROUTES = {
    ("POST", "/scan"),
    ("GET", "/scan/{task_id}"),
}

#: The scan-profile family is a different concern and stays with its own module.
PROFILE_ROUTES = {
    ("GET", "/scan-profiles"),
    ("POST", "/scan-profiles"),
    ("GET", "/scan-profiles/{profile_id}"),
    ("PATCH", "/scan-profiles/{profile_id}"),
    ("DELETE", "/scan-profiles/{profile_id}"),
    ("POST", "/scan-profiles/{profile_id}/run"),
}

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


def test_scan_routes_are_declared_by_the_scan_module_only():
    assert router_routes(SCAN) == SCAN_ROUTES
    assert router_routes(V1) == set()


def test_scan_profiles_keep_their_own_module():
    declared = router_routes(PROFILES)
    assert PROFILE_ROUTES <= declared
    assert {route for route in declared if route[1] == "/scan"} == set()


def test_scan_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in SCAN_ROUTES} <= mounted


def test_the_platform_scan_route_still_wins_over_the_scan_task_route():
    # ``/scan`` and ``/scan/{task_id}`` must not shadow each other or the
    # ``/scan-profiles`` family after the registration order changed.
    paths = [getattr(route, "path", "") for route in app.routes]
    assert paths.index("/api/v1/scan") < paths.index("/api/v1/scan/{task_id}")


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


def test_scan_domain_does_not_reach_into_the_router_workers_or_extensions():
    for node in ast.walk(ast.parse(SCAN.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not module.startswith(("app.workers", "app.api.v1", "app.api.extensions")), (
                module
            )


def test_scan_domain_reuses_the_shared_task_and_asset_boundaries():
    source = SCAN.read_text(encoding="utf-8")
    for shared in (
        "from app.api.dependencies import dispatch_task",
        "from app.api.assets import serialize_asset",
        "from app.api.task_presenter import serialize_task",
        "from app.services.task_service import create_task",
        "from app.services.task_dispatch import NETWORK_SCAN",
    ):
        assert shared in source, shared
    for redefined in (
        "def dispatch_task(",
        "def serialize_task(",
        "def serialize_asset(",
        "def create_task(",
    ):
        assert redefined not in source, redefined
    # Probe-side queueing keeps going through the probe task service, and port
    # selection through the scan service.
    for delegated in (
        "from app.services.probe_task_service import queue_probe_scan",
        "from app.services.scan_service import select_ports",
    ):
        assert delegated in source, delegated


def test_v1_aggregates_the_scan_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(network_scan_router)") == 1
