"""Keep the file-evidence HTTP boundary out of the aggregate router.

The split this guards: ``app.api.files`` declares the file routes and owns the
extension/MIME filter mapping, while probe ownership of an upload and Task-row
serialisation stay in the shared ``app.api`` modules instead of being copied.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
V1 = APP / "api" / "v1.py"
FILES = APP / "api" / "files.py"

#: Frozen file surface: the split must not add, drop or rename one entry.
FILE_ROUTES = {
    ("POST", "/files/upload"),
    ("GET", "/files"),
    ("GET", "/files/{file_id}"),
    ("GET", "/files/{file_id}/download"),
    ("POST", "/files/{file_id}/analyze"),
}

#: HTTP methods a file route may be declared with.
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


def test_file_routes_are_declared_by_the_file_module_only():
    assert router_routes(FILES) == FILE_ROUTES
    assert {route for route in router_routes(V1) if route[1].startswith("/files")} == set()


def test_file_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in FILE_ROUTES} <= mounted


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


def test_file_domain_does_not_reach_into_workers_or_extensions():
    for module in (
        node.module or ""
        for node in ast.walk(ast.parse(FILES.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
    ):
        assert not module.startswith(("app.workers", "app.api.extensions")), module


def test_file_domain_reuses_the_shared_guard_and_task_presenter():
    source = FILES.read_text(encoding="utf-8")
    assert "from app.api.dependencies import" in source
    assert "from app.api.task_presenter import serialize_task" in source
    for redefined in (
        "def upload_probe_id(",
        "def enforce_queue_backpressure(",
        "def serialize_task(",
    ):
        assert redefined not in source, redefined


def test_extension_filter_mapping_is_not_duplicated_back_into_v1():
    source = FILES.read_text(encoding="utf-8")
    assert "FILE_TYPE_ALIASES" in source
    moved = V1.read_text(encoding="utf-8")
    assert "FILE_TYPE_ALIASES" not in moved
    assert "_file_type_candidates" not in moved


def test_v1_aggregates_the_file_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(files_router)") == 1
