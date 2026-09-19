"""Keep the detection and engine HTTP boundaries out of the aggregate router.

The split this guards: ``app.api.detections`` owns the finding list/detail and
the analysis-result view, ``app.api.engines`` owns the engine registry and the
manual pipeline trigger, while detection itself stays in ``app/engine`` and the
engine-name presentation map moves with the domain.
"""

import ast
from pathlib import Path

from app.main import app

APP = Path(__file__).resolve().parents[1] / "app"
V1 = APP / "api" / "v1.py"
DETECTIONS = APP / "api" / "detections.py"
ENGINES = APP / "api" / "engines.py"

#: Frozen detection surface: the split must not add, drop or rename one entry.
DETECTION_ROUTES = {
    ("GET", "/detections"),
    ("GET", "/detections/{detection_id}"),
    ("GET", "/analysis/results"),
}

#: Frozen engine surface.
ENGINE_ROUTES = {
    ("GET", "/engine/registry"),
    ("POST", "/engine/pipeline"),
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


def test_detection_routes_are_declared_by_the_detection_module_only():
    assert router_routes(DETECTIONS) == DETECTION_ROUTES
    leaked = {route for route in router_routes(V1) if route[1].startswith("/detections")}
    assert leaked == set()


def test_engine_routes_are_declared_by_the_engine_module_only():
    assert router_routes(ENGINES) == ENGINE_ROUTES
    assert {route for route in router_routes(V1) if route[1].startswith("/engine")} == set()


def test_detection_and_engine_routes_stay_mounted_under_the_v1_prefix():
    mounted = {getattr(route, "path", "") for route in app.routes}
    expected = {f"/api/v1{path}" for _method, path in DETECTION_ROUTES | ENGINE_ROUTES}
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
    for module in (DETECTIONS, ENGINES):
        for node in ast.walk(ast.parse(module.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith(("app.workers", "app.api.extensions")), (
                    node.module
                )


def test_detection_domain_reuses_the_shared_presenters_instead_of_copying_them():
    source = DETECTIONS.read_text(encoding="utf-8")
    for shared in (
        "from app.api.finding_presenter import _serialize_detection",
        "from app.api.incident_presenter import serialize_incident",
        "from app.api.pcaps import serialize_pcap",
        "from app.api.query_filters import string_time_filter",
        "from app.services.alert_service import serialize_alert",
    ):
        assert shared in source, shared
    for redefined in (
        "def _serialize_detection(",
        "def serialize_incident(",
        "def serialize_pcap(",
        "def serialize_alert(",
        "def string_time_filter(",
    ):
        assert redefined not in source, redefined


def test_engine_domain_reads_the_real_registry_and_rule_inventory():
    source = ENGINES.read_text(encoding="utf-8")
    for shared in (
        "from app.engine import registry",
        "from app.engine.core.pipeline import DetectionPipeline",
        "from app.engine.risk_engine.engine import RiskEngine",
        "from app.api.rule_presenter import rule_file_entries",
        "from app.rules.catalog import CATALOG",
    ):
        assert shared in source, shared
    for forbidden in ("_read_worker_capabilities", "app.workers"):
        assert forbidden not in source, forbidden


def test_engine_presentation_map_moved_out_of_v1_without_being_duplicated():
    source = V1.read_text(encoding="utf-8")
    assert "ENGINE_PRESENTATION" not in source
    assert "ENGINE_PRESENTATION" in ENGINES.read_text(encoding="utf-8")


def test_v1_aggregates_the_detection_and_engine_routers_exactly_once():
    source = V1.read_text(encoding="utf-8")
    assert source.count("include_router(detections_router)") == 1
    assert source.count("include_router(engines_router)") == 1
