"""Keep the task, audit and report boundaries out of the aggregate router.

The split this guards: ``app.api.tasks`` owns the task queue view and
``app.api.reports`` owns the audit summary, log analysis and generated-report
endpoints, while the work itself stays in ``services/task_service.py``,
``services/probe_task_service.py``, ``services/audit_service.py`` and
``services/report_service.py``.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
V1 = APP / "api" / "v1.py"
TASKS = APP / "api" / "tasks.py"
REPORTS = APP / "api" / "reports.py"

#: Frozen task surface: the split must not add, drop or rename one entry.
TASK_ROUTES = {
    ("GET", "/tasks"),
    ("POST", "/tasks"),
    ("GET", "/tasks/{task_id}"),
    ("POST", "/tasks/{task_id}/stop"),
    ("DELETE", "/tasks/{task_id}"),
}

#: Frozen audit/report surface.
REPORT_ROUTES = {
    ("POST", "/audit/logs"),
    ("GET", "/audit/summary"),
    ("POST", "/reports/generate"),
    ("GET", "/reports"),
    ("GET", "/reports/{report_id}/download"),
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


def test_task_routes_are_declared_by_the_task_module_only():
    assert router_routes(TASKS) == TASK_ROUTES
    assert {route for route in router_routes(V1) if route[1].startswith("/tasks")} == set()


def test_report_routes_are_declared_by_the_report_module_only():
    assert router_routes(REPORTS) == REPORT_ROUTES
    leaked = {route for route in router_routes(V1) if route[1].startswith(("/audit", "/reports"))}
    assert leaked == set()


def test_task_and_report_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    expected = {f"/api/v1{path}" for _method, path in TASK_ROUTES | REPORT_ROUTES}
    assert expected <= mounted


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


def test_domains_do_not_reach_into_workers_or_extensions():
    for module in (TASKS, REPORTS):
        for node in ast.walk(ast.parse(module.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith(("app.workers", "app.api.extensions")), (
                    node.module
                )


def test_task_rows_are_serialised_once_by_the_shared_presenter():
    assert "from app.api.task_presenter import serialize_task" in TASKS.read_text(encoding="utf-8")
    for module in (TASKS, REPORTS):
        assert "def serialize_task(" not in module.read_text(encoding="utf-8")
    assert "def serialize_task(" in (APP / "api" / "task_presenter.py").read_text(encoding="utf-8")


def test_report_domain_reuses_the_shared_presenters_instead_of_copying_them():
    source = REPORTS.read_text(encoding="utf-8")
    for shared in (
        "from app.api.assets import serialize_asset",
        "from app.api.data_assets import _serialize_data_asset",
        "from app.api.finding_presenter import _serialize_detection",
        "from app.api.files import serialize_file",
        "from app.api.incident_presenter import serialize_incident",
        "from app.api.pcaps import serialize_anomaly, serialize_pcap",
    ):
        assert shared in source, shared
    for redefined in (
        "def serialize_asset(",
        "def serialize_file(",
        "def serialize_pcap(",
        "def serialize_anomaly(",
        "def serialize_incident(",
        "def _serialize_detection(",
        "def _serialize_data_asset(",
    ):
        assert redefined not in source, redefined


def test_task_and_report_work_stays_in_the_services():
    tasks_source = TASKS.read_text(encoding="utf-8")
    assert "from app.services.task_service import create_task" in tasks_source
    assert "from app.services.probe_task_service import" in tasks_source
    for reimplemented in ("def create_task(", "def expire_probe_tasks(", "def visible_tasks("):
        assert reimplemented not in tasks_source, reimplemented

    reports_source = REPORTS.read_text(encoding="utf-8")
    assert "from app.services.audit_service import audit_summary, log_analysis" in reports_source
    assert "from app.services.report_service import build_summary, render_html, render_pdf" in (
        reports_source
    )
    for reimplemented in (
        "def audit_summary(",
        "def log_analysis(",
        "def build_summary(",
        "def render_html(",
        "def render_pdf(",
    ):
        assert reimplemented not in reports_source, reimplemented


def test_report_serialiser_moved_out_of_v1_without_being_duplicated():
    assert "def _serialize_report(" not in V1.read_text(encoding="utf-8")
    assert "def serialize_report(" in REPORTS.read_text(encoding="utf-8")


def test_v1_aggregates_the_task_and_report_routers_exactly_once():
    source = V1.read_text(encoding="utf-8")
    assert source.count("include_router(tasks_router)") == 1
    assert source.count("include_router(reports_router)") == 1
