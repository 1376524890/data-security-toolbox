"""Keep the 网络资产 inventory out of the aggregate router.

The split this guards: ``app.api.network_assets`` owns the standing
scan-result inventory (``GET /network/assets`` and its summary), which is a
different question from ``app.api.network_scan``'s "start a scan / read this
scan's result". Rows still come from ``assets``, the CVE hits from the stored
findings, and the row shape from ``api/assets.py::serialize_asset``; the domain
owns the paths, the grouping and the response shape only.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
V1 = API / "v1.py"
NETWORK_ASSETS = API / "network_assets.py"
NETWORK_SCAN = API / "network_scan.py"

#: Frozen inventory surface: the split must not add, drop or rename one entry.
NETWORK_ASSET_ROUTES = {
    ("GET", "/network/assets"),
    ("GET", "/network/assets/summary"),
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


def test_network_asset_module_owns_exactly_the_frozen_routes():
    assert router_routes(NETWORK_ASSETS) == NETWORK_ASSET_ROUTES


def test_scan_module_keeps_its_own_surface():
    assert router_routes(NETWORK_SCAN) == {("POST", "/scan"), ("GET", "/scan/{task_id}")}


def test_no_network_asset_route_is_declared_twice():
    seen = []
    for route in app.routes:
        path = getattr(route, "path", "")
        if path.startswith("/api/v1/network/assets"):
            for method in getattr(route, "methods", set()) or set():
                if method in METHODS:
                    seen.append((method, path[len("/api/v1"):]))
    assert sorted(seen) == sorted(NETWORK_ASSET_ROUTES)


def test_the_domain_reuses_the_shared_asset_and_presenter_helpers():
    source = NETWORK_ASSETS.read_text(encoding="utf-8")
    assert "from app.api.assets import serialize_asset" in source
    assert "from app.api.pagination import page_response" in source
    for redefined in ("def serialize_asset(", "def page_response("):
        assert redefined not in source, redefined


def test_v1_aggregates_the_network_asset_router_exactly_once():
    source = V1.read_text(encoding="utf-8")
    assert source.count("include_router(network_assets_router)") == 1
    assert "from app.api.network_assets import" in source
