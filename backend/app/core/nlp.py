"""Building the runtime NLP engine without letting a library fetch a model.

Presidio's default configuration points at ``en_core_web_lg`` and its
``SpacyNlpEngine.load()`` calls ``spacy.cli.download`` whenever that model is
not installed. So the first Presidio call on a networked host silently pip
-installs a 587 MB wheel from GitHub, in the middle of an analysis:

- the delivery environment is offline, where the same call fails instead - the
  code path only ever "works" on a machine that happens to have internet;
- the wheel lands in the container layer, so ``storage_guard`` does not measure
  it and rebuilding the image loses it;
- nothing records that the platform pulled 587 MB out of the customer's network.

Both call sites (``engine/data_engine`` and ``integrations/presidio``) therefore
go through here. The model is named by ``settings.presidio_model``, the engine is
only built when that model is already installed, and downloading is opt-in.
When the model is absent the caller gets a reason string it can report, so the
console says "not checked" instead of "nothing found".
"""
from __future__ import annotations

from typing import Any


def model_installed(name: str) -> bool:
    """Whether a spaCy model is already in the image (no download involved)."""
    try:
        from spacy.util import is_package
    except Exception:
        return False
    try:
        return bool(is_package(name))
    except Exception:
        return False


def build_analyzer(model: str, *, allow_download: bool, language: str = "en",
                   registry_configuration: dict[str, Any] | None = None) -> tuple[Any, str]:
    """An ``AnalyzerEngine`` bound to ``model``, or ``(None, reason)``.

    ``reason`` is empty on success and otherwise a code the caller can store and
    show: ``dependency_missing:*``, ``model_missing:*`` or ``analyzer_failed:*``.
    """
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except Exception as exc:
        return None, f"dependency_missing:{type(exc).__name__}"
    # Checked *before* handing the model name to presidio: ``create_engine``
    # downloads it when it is missing, which is the exact behaviour this module
    # exists to prevent. ``allow_download`` is the deliberate escape hatch.
    if not allow_download and not model_installed(model):
        return None, f"model_missing:{model}"
    try:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": language, "model_name": model}],
        })
        engine = provider.create_engine()
        if registry_configuration is None:
            return AnalyzerEngine(nlp_engine=engine), ""
        return AnalyzerEngine(registry_configuration=registry_configuration, nlp_engine=engine), ""
    except Exception as exc:
        return None, f"analyzer_failed:{type(exc).__name__}"
