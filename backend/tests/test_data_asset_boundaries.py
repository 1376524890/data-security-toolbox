"""Prevent the collection/read split from collapsing back into route dependencies."""

import ast
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"


def imports(path):
    return [
        node.module or ""
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
    ]


def test_data_object_services_have_no_http_worker_or_legacy_dependencies():
    for path in (APP / "services/data_objects").glob("*.py"):
        for module in imports(path):
            assert not module.startswith(("fastapi", "app.api", "app.workers")), (path, module)
            assert module != "app.services.data_object_service", (path, module)
    assert not any(
        m.startswith(("fastapi", "app.api", "app.workers"))
        for m in imports(APP / "services/probe_task_service.py")
    )


def test_data_object_module_dependencies_are_acyclic():
    prefix = "app.services.data_objects."
    graph = {
        p.stem: {m.removeprefix(prefix) for m in imports(p) if m.startswith(prefix)}
        for p in (APP / "services/data_objects").glob("*.py")
    }

    def visit(name, stack):
        assert name not in stack, f"Circular data-object dependency: {stack + [name]}"
        for child in graph.get(name, set()):
            visit(child, stack + [name])

    for name in graph:
        visit(name, [])


def test_collection_consumers_do_not_import_extensions_routes():
    for name in ("profiles.py", "rulesets.py", "data_collection.py", "data_assets.py"):
        assert "app.api.extensions" not in imports(APP / "api" / name)
