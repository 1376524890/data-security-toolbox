"""Keep the admin-session surface out of the aggregate router.

The split this guards: ``app.api.auth`` owns the console login, logout and
identity endpoints, which used to be declared in ``app/api/v1.py``.  Session
storage, cookie handling and password hashing stay in ``app.core.security`` and
the ``AdminSession`` model; the domain owns the paths and response shapes only.

With this batch ``app/api/v1.py`` declares no route of its own any more: it only
aggregates the domain routers, so ``router_routes(V1)`` must stay empty.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
V1 = API / "v1.py"
AUTH = API / "auth.py"

#: Frozen admin-session surface: the split must not add, drop or rename one entry.
AUTH_ROUTES = {
    ("POST", "/auth/login"),
    ("POST", "/auth/logout"),
    ("GET", "/auth/me"),
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


def test_auth_routes_are_declared_by_the_auth_module_only():
    assert router_routes(AUTH) == AUTH_ROUTES
    assert router_routes(V1) == set()


def test_v1_is_pure_aggregation_after_this_split():
    source = V1.read_text(encoding="utf-8")
    for gone in (
        "def admin_login(",
        "def health(",
        "def start_scan(",
        "def import_test(",
        "def _require_test_data_import(",
    ):
        assert gone not in source, gone


def test_auth_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in AUTH_ROUTES} <= mounted


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


def test_auth_domain_does_not_reach_into_the_router_workers_or_extensions():
    for node in ast.walk(ast.parse(AUTH.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not module.startswith(("app.workers", "app.api.v1", "app.api.extensions")), (
                module
            )


def test_auth_domain_reuses_the_shared_session_boundaries():
    source = AUTH.read_text(encoding="utf-8")
    for shared in (
        "from app.core.security import",
        "from app.core.database import get_db",
        "from app.models import AdminSession, User",
        "from app.schemas import LoginRequest",
    ):
        assert shared in source, shared
    for redefined in (
        "def verify_password(",
        "def create_admin_session(",
        "def hash_token(",
        "def set_admin_cookie(",
        "def clear_admin_cookie(",
        "def ensure_admin(",
    ):
        assert redefined not in source, redefined
    # The session cookie name keeps coming from settings, never from a literal.
    assert "settings.cookie_name" in source


def test_v1_aggregates_the_auth_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(auth_router)") == 1
