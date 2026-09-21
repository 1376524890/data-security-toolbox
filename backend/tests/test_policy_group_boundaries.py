"""Keep the policy-group surface in one module, mounted exactly once.

Policy groups are the selectable rule bundle used at task dispatch. The rules
themselves stay in the shared rule library; this surface only writes the group
table, so it must not grow a second rule definition and must not be declared by
``v1.py`` (which only aggregates) or any other domain.
"""
import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
V1 = API / "v1.py"
GROUPS = API / "policy_groups.py"

#: Frozen policy-group surface: the split must not add, drop or rename an entry.
GROUP_ROUTES = {
    ("GET", "/policy-groups"),
    ("POST", "/policy-groups"),
    ("GET", "/policy-groups/{group_id}"),
    ("PATCH", "/policy-groups/{group_id}"),
    ("DELETE", "/policy-groups/{group_id}"),
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


def test_group_routes_are_declared_by_the_policy_group_module_only():
    assert router_routes(GROUPS) == GROUP_ROUTES
    assert {route for route in router_routes(V1) if route[1].startswith("/policy-groups")} == set()


def test_policy_group_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in GROUP_ROUTES} <= mounted


def test_v1_aggregates_the_policy_group_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(policy_groups_router)") == 1


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


def test_policy_group_service_does_not_redefine_rule_content():
    """A group references rules; it must never carry a second rule definition."""
    source = (APP / "services" / "policy_groups.py").read_text(encoding="utf-8")
    for redefined in ("def scan_all(", "def analyst_rules(", "def rule_file_entries("):
        assert redefined not in source, redefined
