"""Keep the platform-asset HTTP boundary out of the aggregate router.

The split this guards: ``app.api.assets`` declares the inventory routes and the
asset-row shape, while the incident/IOC row shapes and the datetime
normalisation live in shared presenter/core modules instead of being copied
into the domain.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
V1 = APP / "api" / "v1.py"
ASSETS = APP / "api" / "assets.py"
DATETIMES = APP / "core" / "datetimes.py"
PRESENTERS = (APP / "api" / "incident_presenter.py", APP / "api" / "ioc_presenter.py")

#: Frozen asset surface: the split must not add, drop or rename one entry.
ASSET_ROUTES = {
    ("GET", "/assets"),
    ("GET", "/assets/summary"),
    ("GET", "/assets/relations"),
    ("GET", "/assets/{asset_id}"),
}

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


def defined_names(path):
    return {
        node.name
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def test_asset_routes_are_declared_by_the_asset_module_only():
    assert router_routes(ASSETS) == ASSET_ROUTES
    assert {route for route in router_routes(V1) if route[1].startswith("/assets")} == set()


def test_asset_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in ASSET_ROUTES} <= mounted


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


def test_asset_domain_does_not_reach_into_workers_or_extensions():
    for module in (
        node.module or ""
        for node in ast.walk(ast.parse(ASSETS.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
    ):
        assert not module.startswith(("app.workers", "app.api.extensions")), module


def test_asset_domain_reuses_the_shared_presenters_instead_of_copying_them():
    source = ASSETS.read_text(encoding="utf-8")
    assert "from app.api.finding_presenter import" in source
    assert "from app.api.incident_presenter import serialize_incident" in source
    assert "from app.api.ioc_presenter import serialize_ioc" in source
    for redefined in (
        "def _serialize_detection(",
        "def serialize_incident(",
        "def serialize_ioc(",
        "def aware(",
    ):
        assert redefined not in source, redefined


def test_shared_row_shapes_are_not_duplicated_back_into_v1():
    moved = V1.read_text(encoding="utf-8")
    for gone in (
        "def _serialize_asset(",
        "def _serialize_incident(",
        "def _serialize_ioc(",
        "def _aware(",
    ):
        assert gone not in moved, gone
    assert "_serialize_asset" not in moved
    assert "_serialize_incident" not in moved
    assert "_serialize_ioc" not in moved


def test_datetime_normalisation_has_a_single_implementation():
    assert "aware" in defined_names(DATETIMES)
    for path in (ASSETS, *PRESENTERS):
        assert "def aware(" not in path.read_text(encoding="utf-8")


def test_v1_aggregates_the_asset_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(assets_router)") == 1
