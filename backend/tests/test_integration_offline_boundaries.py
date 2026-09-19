"""Keep the integration and offline-import HTTP boundary out of the aggregate router.

The split this guards: ``app.api.integrations`` owns the adapter catalogue, the
manual adapter run and the whole ``/offline`` surface (bundle resources, manual
CVEs and the asynchronous Grype jobs), which used to be split between
``app/api/v1.py`` and ``app/api/libraries.py``.  Adapter metadata/execution stay
in ``app.integrations``, the Grype database in ``services/grype_library.py``,
alerts in ``services/alert_service.py`` and the worker capability/rule
inventory ``/health`` also reads in ``app/api/runtime_status.py``.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
V1 = API / "v1.py"
INTEGRATIONS = API / "integrations.py"
LIBRARIES = API / "libraries.py"
RUNTIME_STATUS = API / "runtime_status.py"

#: Frozen integration/offline surface: the split must not add, drop or rename one entry.
INTEGRATION_ROUTES = {
    ("GET", "/integrations"),
    ("POST", "/integrations/{name}/analyze"),
    ("POST", "/integrations/offline/upload"),
    ("POST", "/integrations/offline/import"),
    ("GET", "/offline/resources"),
    ("GET", "/offline/cves"),
    ("POST", "/offline/upload"),
    ("POST", "/offline/cves"),
    ("POST", "/offline/grype/update"),
    ("POST", "/offline/grype/import"),
    ("GET", "/offline/grype/jobs/{identifier}"),
}

#: The rule-authoring surface ``libraries.py`` keeps after the move.
LIBRARY_ROUTES = {
    ("GET", "/dlp/rules"),
    ("POST", "/dlp/rules"),
    ("POST", "/dlp/rules/presidio/update"),
    ("PATCH", "/dlp/rules/{identifier}"),
    ("GET", "/rule-sources"),
    ("POST", "/rules/sync"),
    ("POST", "/rules"),
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


def test_integration_routes_are_declared_by_the_integrations_module_only():
    assert router_routes(INTEGRATIONS) == INTEGRATION_ROUTES
    for other in (V1, LIBRARIES):
        declared = router_routes(other)
        assert {route for route in declared if route[1].startswith("/integrations")} == set()
        assert {route for route in declared if route[1].startswith("/offline")} == set()


def test_rule_authoring_routes_stayed_in_the_libraries_module():
    declared = router_routes(LIBRARIES)
    assert LIBRARY_ROUTES <= declared
    # The vulnerability-library maintenance moved out, so no /offline path is left.
    assert {route for route in declared if route[1].startswith("/offline")} == set()


def test_integration_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in INTEGRATION_ROUTES} <= mounted
    assert {f"/api/v1{path}" for _method, path in LIBRARY_ROUTES} <= mounted


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


def test_integration_domain_does_not_reach_into_the_router_workers_or_extensions():
    for node in ast.walk(ast.parse(INTEGRATIONS.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not module.startswith(("app.workers", "app.api.v1", "app.api.extensions")), (
                module
            )


def test_integration_domain_reuses_the_shared_boundaries():
    source = INTEGRATIONS.read_text(encoding="utf-8")
    for shared in (
        "from app.api.pagination import page_response",
        "from app.api.runtime_status import",
        "from app.core.storage import safe_path",
        "from app.integrations import integration_registry",
        "from app.integrations.offline_manager import",
        "from app.integrations.runner import run_adapter",
        "from app.services.alert_service import",
        "from app.services.rule_library import atomic_json",
        "from app.incident_engine.engine import IncidentEngine",
    ):
        assert shared in source, shared
    for redefined in (
        "def page_response(",
        "def safe_path(",
        "def read_worker_capabilities(",
        "def merge_capability(",
        "def engine_rule_counts(",
        "def import_uploaded_offline(",
    ):
        assert redefined not in source, redefined
    # The Grype database itself stays a service, imported where it is used.
    assert "from app.services.grype_library import" in source


def test_worker_capability_reading_is_shared_with_health():
    v1_source = V1.read_text(encoding="utf-8")
    status_source = RUNTIME_STATUS.read_text(encoding="utf-8")
    for name in ("read_worker_capabilities", "merge_capability", "engine_rule_counts"):
        assert f"def {name}(" in status_source, name
        assert f"def _{name}(" not in v1_source, name
    assert "from app.api.runtime_status import" in v1_source


def test_v1_aggregates_the_integrations_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(integrations_router)") == 1
