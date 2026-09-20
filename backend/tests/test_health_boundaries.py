"""Keep the platform-health read out of the aggregate router.

The split this guards: ``app.api.health`` owns ``GET /health``, which used to be
declared in ``app/api/v1.py``.  The worker capability and rule-inventory reads
stay in ``app/api/runtime_status.py`` (shared with ``/integrations``), the queue
depth in ``services/task_dispatch.py`` and the probe row shape in
``api/probe_presenter.py``; the domain owns the path and the response shape only.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
V1 = API / "v1.py"
HEALTH = API / "health.py"
RUNTIME_STATUS = API / "runtime_status.py"

#: Frozen health surface: the split must not add, drop or rename the entry.
HEALTH_ROUTES = {("GET", "/health")}

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


def test_health_route_is_declared_by_the_health_module_only():
    assert router_routes(HEALTH) == HEALTH_ROUTES
    declared = {route for route in router_routes(V1) if route[1].startswith("/health")}
    assert declared == set()


def test_health_route_stays_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in HEALTH_ROUTES} <= mounted


def test_health_stays_exempt_from_the_admin_session_check():
    # The container probe and the console poll /api/v1/health unauthenticated.
    assert '"/api/v1/health"' in (APP / "main.py").read_text(encoding="utf-8")


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


def test_health_domain_does_not_reach_into_the_router_workers_or_extensions():
    for node in ast.walk(ast.parse(HEALTH.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not module.startswith(("app.workers", "app.api.v1", "app.api.extensions")), (
                module
            )


def test_health_reuses_the_shared_reads_instead_of_copying_them():
    source = HEALTH.read_text(encoding="utf-8")
    for shared in (
        "from app.api.runtime_status import engine_rule_counts, merge_capability,"
        " read_worker_capabilities",
        "from app.api.probe_presenter import serialize_probe",
        "from app.services.task_dispatch import queue_depth",
    ):
        assert shared in source, shared
    for redefined in (
        "def read_worker_capabilities(",
        "def merge_capability(",
        "def engine_rule_counts(",
        "def serialize_probe(",
        "def queue_depth(",
    ):
        assert redefined not in source, redefined
    status_source = RUNTIME_STATUS.read_text(encoding="utf-8")
    for name in ("read_worker_capabilities", "merge_capability", "engine_rule_counts"):
        assert f"def {name}(" in status_source, name


def test_v1_aggregates_the_health_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(health_router)") == 1
