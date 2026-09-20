"""Keep the alert HTTP boundary out of the aggregate router.

The split this guards: ``app.api.alerts`` declares the triage queue, the live
stream and the alert detail view, while suppression/delivery stay in
``services/alert_service.py``, the row shapes come from the shared presenters,
and the probe/rule lookups live once in ``probe_presenter``/``rule_presenter``.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
V1 = APP / "api" / "v1.py"
ALERTS = APP / "api" / "alerts.py"
PROBE_PRESENTER = APP / "api" / "probe_presenter.py"
RULE_PRESENTER = APP / "api" / "rule_presenter.py"

#: Frozen alert surface: the split must not add, drop or rename one entry.
ALERT_ROUTES = {
    ("GET", "/alerts"),
    ("GET", "/alerts/summary"),
    ("GET", "/alerts/stream"),
    ("GET", "/alerts/{alert_id}"),
    ("PATCH", "/alerts/{alert_id}"),
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


def test_alert_routes_are_declared_by_the_alert_module_only():
    assert router_routes(ALERTS) == ALERT_ROUTES
    assert {route for route in router_routes(V1) if route[1].startswith("/alerts")} == set()


def test_alert_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    assert {f"/api/v1{path}" for _method, path in ALERT_ROUTES} <= mounted


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


def test_alert_domain_does_not_reach_into_workers_or_extensions():
    for module in (
        node.module or ""
        for node in ast.walk(ast.parse(ALERTS.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
    ):
        assert not module.startswith(("app.workers", "app.api.extensions")), module


def test_alert_domain_reuses_the_shared_presenters_instead_of_copying_them():
    source = ALERTS.read_text(encoding="utf-8")
    for shared in (
        "from app.api.finding_presenter import",
        "from app.api.incident_presenter import serialize_incident",
        "from app.api.ioc_presenter import serialize_ioc",
        "from app.api.assets import serialize_asset",
        "from app.api.data_assets import",
        "from app.api.pcaps import serialize_pcap",
        "from app.api.probe_presenter import serialize_probe",
        "from app.api.rule_presenter import rule_definition",
    ):
        assert shared in source, shared
    for redefined in (
        "def _serialize_detection(",
        "def serialize_incident(",
        "def serialize_ioc(",
        "def serialize_asset(",
        "def serialize_probe(",
        "def rule_definition(",
    ):
        assert redefined not in source, redefined


def test_alert_suppression_and_delivery_stay_in_the_service():
    source = ALERTS.read_text(encoding="utf-8")
    assert "from app.services.alert_service import" in source
    for reimplemented in (
        "def publish_alert(",
        "def list_alert_hits(",
        "def event_type_for_status(",
    ):
        assert reimplemented not in source, reimplemented


def test_probe_and_rule_lookups_are_not_duplicated_back_into_v1():
    moved = V1.read_text(encoding="utf-8")
    for gone in (
        "def _serialize_probe(",
        "def _rule_definition(",
        "def _rule_file_entries(",
    ):
        assert gone not in moved, gone
    assert "def serialize_probe(" in PROBE_PRESENTER.read_text(encoding="utf-8")
    assert "def rule_definition(" in RULE_PRESENTER.read_text(encoding="utf-8")
    assert "def rule_file_entries(" in RULE_PRESENTER.read_text(encoding="utf-8")


def test_v1_aggregates_the_alert_router_exactly_once():
    assert V1.read_text(encoding="utf-8").count("include_router(alerts_router)") == 1
