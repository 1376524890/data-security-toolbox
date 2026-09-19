"""Keep the capture HTTP boundary out of the aggregate router.

The split this guards: ``app.api.pcaps`` declares the capture routes,
``app.api.dependencies`` owns the probe-upload guards, and ``app.api.v1`` only
aggregates routers - so every path is registered exactly once and the capture
surface did not move while the module did.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
V1 = APP / "api" / "v1.py"
PCAPS = APP / "api" / "pcaps.py"
DEPENDENCIES = APP / "api" / "dependencies.py"

#: Frozen capture surface: the split must not add, drop or rename one entry.
CAPTURE_ROUTES = {
    ("POST", "/pcaps/upload"),
    ("GET", "/pcaps"),
    ("GET", "/pcaps/{pcap_id}"),
    ("POST", "/pcaps/{pcap_id}/analyze"),
    ("GET", "/pcaps/{pcap_id}/flows"),
    ("GET", "/pcaps/{pcap_id}/packets"),
    ("GET", "/pcaps/{pcap_id}/anomalies"),
    ("GET", "/pcaps/{pcap_id}/protocols"),
    ("GET", "/pcaps/{pcap_id}/traffic"),
    ("GET", "/pcaps/{pcap_id}/dns"),
    ("GET", "/pcaps/{pcap_id}/http"),
    ("GET", "/pcaps/{pcap_id}/tls"),
    ("GET", "/pcaps/{pcap_id}/files"),
    ("GET", "/pcaps/{pcap_id}/files/{file_id}"),
    ("GET", "/pcaps/{pcap_id}/alerts"),
    ("GET", "/pcaps/{pcap_id}/packets/{packet_id}"),
    ("GET", "/pcaps/{pcap_id}/streams/{stream_id}"),
    ("GET", "/pcaps/{pcap_id}/files/{file_id}/download"),
}

#: Guards an upload needs before it may create a task row.
UPLOAD_GUARDS = ("upload_probe_id", "enforce_queue_backpressure")

#: HTTP methods a capture route may be declared with.
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


def imported_modules(path):
    return [
        node.module or ""
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
    ]


def test_capture_routes_are_declared_by_the_capture_module_only():
    assert router_routes(PCAPS) == CAPTURE_ROUTES
    assert {route for route in router_routes(V1) if "/pcaps" in route[1]} == set()


def test_capture_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in CAPTURE_ROUTES} <= mounted


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


def test_capture_domain_does_not_reach_into_workers_or_extensions():
    for module in imported_modules(PCAPS):
        assert not module.startswith(("app.workers", "app.api.extensions")), module


def test_upload_guards_live_in_the_shared_dependency_module():
    defined = {
        node.name
        for node in ast.parse(DEPENDENCIES.read_text(encoding="utf-8")).body
        if isinstance(node, ast.FunctionDef)
    }
    assert set(UPLOAD_GUARDS) <= defined
    assert "from app.api.dependencies import" in PCAPS.read_text(encoding="utf-8")
    # No route module may keep a private copy once the guard is shared.
    for path in (APP / "api").rglob("*.py"):
        if path == DEPENDENCIES:
            continue
        source = path.read_text(encoding="utf-8")
        for guard in UPLOAD_GUARDS:
            assert f"def {guard}(" not in source, (path.name, guard)


def test_v1_aggregates_the_capture_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(pcaps_router)") == 1
