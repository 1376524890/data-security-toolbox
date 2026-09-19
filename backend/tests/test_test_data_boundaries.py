"""Keep the manual test pack out of the aggregate router.

The split this guards: ``app.api.test_data`` owns ``/test/import``,
``/test/clear`` and ``/test/status``, which used to be declared in
``app/api/v1.py``.  The import/clear/status implementation stays in
``services/test_service.py`` and the opt-in guard behind
``settings.test_data_import_enabled`` moves with the domain, so the delivery
constraint (no test data unless an operator opts in) is enforced in one place.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
V1 = API / "v1.py"
TEST_DATA = API / "test_data.py"
TEST_SERVICE = APP / "services" / "test_service.py"

#: Frozen test-pack surface: the split must not add, drop or rename one entry.
TEST_ROUTES = {
    ("POST", "/test/import"),
    ("POST", "/test/clear"),
    ("GET", "/test/status"),
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


def test_test_routes_are_declared_by_the_test_data_module_only():
    assert router_routes(TEST_DATA) == TEST_ROUTES
    assert router_routes(V1) == set()


def test_test_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in TEST_ROUTES} <= mounted


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


def test_test_data_domain_does_not_reach_into_the_router_workers_or_extensions():
    for node in ast.walk(ast.parse(TEST_DATA.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not module.startswith(("app.workers", "app.api.v1", "app.api.extensions")), (
                module
            )


def test_the_opt_in_guard_moved_with_the_domain_and_is_not_duplicated():
    source = TEST_DATA.read_text(encoding="utf-8")
    assert "def _require_test_data_import(" in source
    assert "def _require_test_data_import(" not in V1.read_text(encoding="utf-8")
    assert "settings.test_data_import_enabled" in source
    assert "raise HTTPException(403" in source
    # Both write paths go through the guard; the read path must not.
    assert source.count("    _require_test_data_import()") == 2
    assert source.count("def _require_test_data_import(") == 1


def test_test_data_domain_reuses_the_test_service_instead_of_copying_it():
    source = TEST_DATA.read_text(encoding="utf-8")
    assert (
        "from app.services.test_service import clear_test_data, import_test_data, test_status"
        in source
    )
    for redefined in (
        "def import_test_data(",
        "def clear_test_data(",
        "def test_status(",
    ):
        assert redefined not in source, redefined
    service_source = TEST_SERVICE.read_text(encoding="utf-8")
    for defined in ("def import_test_data(", "def clear_test_data(", "def test_status("):
        assert defined in service_source, defined


def test_v1_aggregates_the_test_data_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(test_data_router)") == 1
