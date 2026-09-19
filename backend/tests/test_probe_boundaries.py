"""Keep the probe HTTP boundary out of the aggregate router.

The split this guards: ``app.api.probes`` owns probe registration, heartbeat,
inventory, metrics, task views and remote removal, while probe authentication
stays in ``core/security.py``/``api/dependencies.py``, task rows in
``services/task_service.py`` and the queue hop behind the
``services/task_dispatch.py`` port.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
V1 = APP / "api" / "v1.py"
PROBES = APP / "api" / "probes.py"
DEPENDENCIES = APP / "api" / "dependencies.py"

#: Frozen probe surface: the split must not add, drop or rename one entry.
PROBE_ROUTES = {
    ("POST", "/probes/register"),
    ("POST", "/probes/{probe_id}/heartbeat"),
    ("GET", "/probes"),
    ("DELETE", "/probes/{probe_id}"),
    ("POST", "/probes/{probe_id}/analyze"),
    ("GET", "/probes/{probe_id}/tasks"),
    ("POST", "/probes/{probe_id}/scan"),
    ("GET", "/probes/{probe_id}/metrics"),
    ("GET", "/crypto/probe-profile"),
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


def test_probe_routes_are_declared_by_the_probe_module_only():
    assert router_routes(PROBES) == PROBE_ROUTES
    assert {route for route in router_routes(V1) if route[1].startswith("/probes")} == set()
    assert {route for route in router_routes(V1) if route[1].startswith("/crypto")} == set()


def test_probe_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in PROBE_ROUTES} <= mounted


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


def test_probe_domain_does_not_reach_into_workers_or_extensions():
    for node in ast.walk(ast.parse(PROBES.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith(("app.workers", "app.api.extensions")), (
                node.module
            )


def test_probe_ownership_and_rows_reuse_the_shared_helpers():
    source = PROBES.read_text(encoding="utf-8")
    for shared in (
        "from app.api.dependencies import dispatch_task",
        "from app.api.pagination import page_response, paginate",
        "from app.api.probe_presenter import serialize_probe",
        "from app.api.task_presenter import serialize_task",
        "from app.core.datetimes import aware",
        "from app.core.security import (",
    ):
        assert shared in source, shared
    for redefined in (
        "def authenticated_probe(",
        "def require_probe_headers(",
        "def serialize_probe(",
        "def serialize_task(",
        "def aware(",
        "def paginate(",
    ):
        assert redefined not in source, redefined


def test_probe_work_stays_behind_the_service_and_queue_port():
    source = PROBES.read_text(encoding="utf-8")
    for shared in (
        "from app.services.probe_service import",
        "from app.services.probe_task_service import expire_probe_tasks, visible_tasks",
        "from app.services.task_dispatch import",
        "from app.services.task_service import create_task",
        "from app.deployment.enrollment import",
        "from app.deployment.removal import create_removal_deployment",
    ):
        assert shared in source, shared
    # The queue port is the only sanctioned way to reach Celery.
    assert "dispatch_task_row(" not in source
    assert "celery_app" not in source


def test_latest_ruleset_version_moved_with_the_heartbeat():
    assert "def _latest_ruleset_version(" not in V1.read_text(encoding="utf-8")
    assert "def _latest_ruleset_version(" in PROBES.read_text(encoding="utf-8")


def test_dispatch_helper_is_shared_from_the_dependencies_module():
    source = DEPENDENCIES.read_text(encoding="utf-8")
    assert "def dispatch_task(" in source
    assert "from app.services.task_dispatch import dispatch_task_row" in source


def test_v1_aggregates_the_probe_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(probes_router)") == 1
