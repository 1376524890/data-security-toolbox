"""Keep the target helpers in one module, mounted exactly once, and read-only."""
import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
V1 = API / "v1.py"
TARGETS = API / "targets.py"
SERVICE = APP / "services" / "target_tree.py"

#: Frozen target surface: the wizard depends on exactly these two calls.
TARGET_ROUTES = {
    ("POST", "/targets/test"),
    ("POST", "/targets/browse"),
}

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


def router_routes(path):
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


def test_target_routes_are_declared_by_the_targets_module_only():
    assert router_routes(TARGETS) == TARGET_ROUTES
    assert {route for route in router_routes(V1) if route[1].startswith("/targets")} == set()


def test_target_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in TARGET_ROUTES} <= mounted


def test_v1_aggregates_the_targets_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(targets_router)") == 1


def test_target_service_never_writes():
    source = SERVICE.read_text(encoding="utf-8")
    for write in ("db.add(", "db.commit(", "db.delete(", "db.flush(", "session.add("):
        assert write not in source, write
