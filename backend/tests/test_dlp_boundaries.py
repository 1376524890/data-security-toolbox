"""Keep the network DLP domain layered and the rule source single-mapped.

Two couplings this guards:

* ``app.services.dlp_service`` held the DLP policy, the "is this our own
  traffic" identity, packet reassembly, HTTP extraction and the detection stage
  in one 460-line module, and the rule store imported a formatter out of it --
  so the rule store and the network DLP stage imported each other. The domain is
  now ``app/services/dlp/{constants,policy,self_traffic,capture,detect}`` and
  ``dlp_service`` only re-exports it.
* the console's rule store reached a probe through a second mapping of the same
  JSON in ``ruleset_service``, which dropped the shape check the platform
  applied. Both sides now build their rules from ``rule_library.stored_rule``.
"""
import ast
from pathlib import Path

from app.services import dlp, dlp_service, masking, rule_library, ruleset_service, sensitive_engine

APP = Path(__file__).resolve().parents[1] / "app"
DLP = APP / "services" / "dlp"
LAYERS = ("constants", "policy", "self_traffic", "capture", "detect")


def imported_modules(path: Path) -> set[str]:
    """Every module a file imports, wherever in the file the import sits."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def test_the_domain_is_one_module_per_responsibility():
    modules = sorted(path.stem for path in DLP.glob("*.py") if path.stem != "__init__")
    assert modules == sorted(LAYERS)


def test_no_layer_reaches_the_http_router_or_the_worker_entry():
    for layer in LAYERS:
        modules = imported_modules(DLP / f"{layer}.py")
        assert not {name for name in modules if name.startswith(("app.api", "app.workers"))}, layer


def test_only_the_detection_stage_runs_the_shared_sensitive_engine():
    for layer in ("constants", "policy", "self_traffic", "capture"):
        assert "sensitive_engine" not in (DLP / f"{layer}.py").read_text(encoding="utf-8"), layer
    assert "sensitive_engine" in (DLP / "detect.py").read_text(encoding="utf-8")


def test_the_rule_store_no_longer_imports_the_dlp_domain():
    store = (APP / "services" / "rule_library.py").read_text(encoding="utf-8")
    assert "dlp_service" not in store
    assert "services.dlp" not in store


def test_the_dlp_facade_only_reexports_the_domain():
    for name in dlp_service.__all__:
        source = dlp if hasattr(dlp, name) else masking
        assert getattr(dlp_service, name) is getattr(source, name), name
    assert "masked" in dlp_service.__all__
    assert rule_library.masked is masking.masked


def test_one_store_rule_mapping_feeds_the_engine_and_the_rule_pack():
    store = (APP / "services" / "rule_library.py").read_text(encoding="utf-8")
    assert "def stored_rule(" in store and "SOURCE_BY_STORE" in store
    assert "stored_rule" in (APP / "services" / "sensitive_engine.py").read_text(encoding="utf-8")
    packs = (APP / "services" / "ruleset_service.py").read_text(encoding="utf-8")
    assert "sensitive_engine.analyst_rules()" in packs
    # The second reading of the store, with its own provenance table, is gone.
    assert "managed_rules" not in packs
    assert "_SOURCE_BY_LEGACY" not in packs


def test_the_rule_pack_carries_the_shape_check_the_platform_applies(tmp_path, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "integration_dir", tmp_path)
    store_rule = rule_library.save_manual_rule({"name": "email rule", "pattern": r"\S+@\S+",
                                                "entity": "EMAIL_ADDRESS"})
    engine_rule = next(rule for rule in sensitive_engine.analyst_rules()
                       if rule["rule_id"] == store_rule["id"])
    assert engine_rule["entity"] == sensitive_engine.canonical_entity("EMAIL_ADDRESS")
    assert engine_rule["validator"] == "email_shape"

    payload = ruleset_service.rule_payload(engine_rule, source=engine_rule["rule_source"])
    assert payload["validator"] == engine_rule["validator"]
    assert payload["entity"] == engine_rule["entity"]
    assert payload["rule_source"] == "manual"

    # The pack a probe downloads has to keep working with the validator on it:
    # publishing validates the rules for real, by loading them into an engine.
    package, prepared = ruleset_service.build_pack([payload], "boundary-1")
    assert package and prepared[0]["validator"] == "email_shape"
