"""Keep the detection-rule catalogue out of the aggregate router.

The split this guards: ``app.api.rules`` owns the engine-rule surface - browsing
the rule corpus, reading one rule, the per-engine provenance, the online
upstream refresh and the manual Suricata/YARA import - which used to be split
between ``app/api/v1.py`` and ``app/api/libraries.py``.  Rule enumeration stays
in ``api/rule_presenter.py``, provenance in ``app.rules.catalog``/``library``,
the refresh in ``app.rules.sync``; the DLP/sensitive rule catalogue stays a
separate family in ``app/api/libraries.py``.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
API = APP / "api"
V1 = API / "v1.py"
RULES = API / "rules.py"
LIBRARIES = API / "libraries.py"
PRESENTER = API / "rule_presenter.py"

#: Frozen detection-rule surface: the split must not add, drop or rename one entry.
RULE_ROUTES = {
    ("GET", "/rules"),
    ("GET", "/rules/content"),
    ("GET", "/rule-sources"),
    ("POST", "/rules/sync"),
    ("POST", "/rules"),
}

#: The sensitive-data rule family that stays with the libraries module.
LIBRARY_ROUTES = {
    ("GET", "/dlp/rules"),
    ("POST", "/dlp/rules"),
    ("POST", "/dlp/rules/presidio/update"),
    ("PATCH", "/dlp/rules/{identifier}"),
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


def test_rule_routes_are_declared_by_the_rules_module_only():
    assert router_routes(RULES) == RULE_ROUTES
    for other in (V1, LIBRARIES):
        declared = {route for route in router_routes(other) if not route[1].startswith("/dlp")}
        assert declared & RULE_ROUTES == set()


def test_dlp_rule_catalogue_stayed_in_the_libraries_module():
    declared = router_routes(LIBRARIES)
    assert LIBRARY_ROUTES <= declared
    assert {route for route in declared if route[1].startswith("/rules")} == set()


def test_rule_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in RULE_ROUTES} <= mounted
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


def test_rule_domain_does_not_reach_into_the_router_workers_or_extensions():
    for node in ast.walk(ast.parse(RULES.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert not module.startswith(("app.workers", "app.api.v1", "app.api.extensions")), (
                module
            )


def test_rule_domain_reuses_the_shared_boundaries():
    source = RULES.read_text(encoding="utf-8")
    for shared in (
        "from app.api.rule_presenter import rule_file_entries",
        "from app.core.config import settings",
        "from app.models import SystemSetting",
        "from app.services.audit_service import record_audit",
    ):
        assert shared in source, shared
    for redefined in (
        "def rule_file_entries(",
        "def managed_rules(",
        "def sources(",
        "def refresh(",
        "def import_uploaded_offline(",
    ):
        assert redefined not in source, redefined
    # The rule file enumeration itself stays the presenter's job.
    assert "rule_file_entries(" in source


def test_rule_sources_read_the_catalog_and_sync_service_in_place():
    source = RULES.read_text(encoding="utf-8")
    for shared in (
        "from app.rules.catalog import CATALOG",
        "from app.rules import sync as rule_sync",
        "from app.rules import library",
    ):
        assert shared in source, shared


def test_rule_presenter_is_shared_with_the_other_domains():
    source = PRESENTER.read_text(encoding="utf-8")
    assert "def rule_file_entries(" in source
    assert "rule_file_entries" in (API / "engines.py").read_text(encoding="utf-8")


def test_v1_aggregates_the_rules_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(rules_router)") == 1
