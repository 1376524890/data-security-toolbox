"""Keep the assessment surface read-only, in one module, mounted exactly once."""
import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
SERVICES = APP / "services" / "assessments"
V1 = API / "v1.py"
ASSESSMENTS = API / "assessments.py"

#: Frozen read-only assessment surface: the split must not add, drop or rename one.
ASSESSMENT_ROUTES = {
    ("GET", "/assessments/overview"),
    ("GET", "/assessments/classification"),
    ("GET", "/assessments/exposure"),
    ("GET", "/assessments/flow"),
    ("GET", "/assessments/egress"),
    ("GET", "/assessments/compliance"),
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


def test_assessment_routes_are_declared_by_the_assessment_module_only():
    assert router_routes(ASSESSMENTS) == ASSESSMENT_ROUTES
    assert {route for route in router_routes(V1) if route[1].startswith("/assessments")} == set()


def test_assessment_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in ASSESSMENT_ROUTES} <= mounted


def test_v1_aggregates_the_assessment_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(assessments_router)") == 1


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


def test_assessment_service_never_writes():
    """The aggregations are read-only: no SQLAlchemy session mutation at all."""
    offenders = []
    for path in sorted(SERVICES.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for write in ("db.add(", "db.commit(", "db.delete(", "db.flush(", "db.merge(",
                      "session.add(", "session.commit(", "session.delete("):
            if write in source:
                offenders.append(f"{path.name}: {write}")
    assert offenders == []
