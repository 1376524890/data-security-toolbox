"""The platform must never install an NLP model behind the operator's back.

Presidio's ``SpacyNlpEngine.load()`` calls ``spacy.cli.download`` for whatever
model its configuration names, and presidio's own default is ``en_core_web_lg``
- a 587 MB wheel pulled from GitHub by ``pip``. That happened on the first
analysis of any networked host: wrong for an offline-delivery product, invisible
to ``storage_guard`` (the wheel lands in the container layer, not
``STORAGE_DIR``), and nothing an audit can point at afterwards.

These tests pin the three parts of the guard: the pinned model is not presidio's
default, a missing model is reported rather than fetched, and the data engine
turns that report into a status a document can carry.
"""
from __future__ import annotations

import pytest
from app.core.config import settings
from app.core.nlp import build_analyzer, model_installed

pytest.importorskip("spacy.cli")


def test_the_pinned_model_is_not_presidios_587mb_default() -> None:
    assert settings.presidio_model
    assert settings.presidio_model != "en_core_web_lg"


def test_downloading_a_model_is_opt_in() -> None:
    assert settings.presidio_allow_model_download is False


def test_a_missing_model_is_reported_and_never_fetched(monkeypatch: pytest.MonkeyPatch) -> None:
    import spacy.cli

    fetched: list[str] = []
    monkeypatch.setattr(spacy.cli, "download", lambda *args, **kwargs: fetched.append(str(args)))
    monkeypatch.setattr("app.core.nlp.model_installed", lambda name: False)

    analyzer, reason = build_analyzer("definitely_not_installed_model", allow_download=False)

    assert analyzer is None
    assert fetched == [], "模型缺失时不得触发下载"
    assert reason == "model_missing:definitely_not_installed_model"


def test_a_model_that_is_installed_is_looked_up_without_downloading() -> None:
    """``is_package`` is a filesystem lookup, not a network call."""
    assert model_installed("definitely_not_installed_model") is False


def test_the_engine_reports_a_missing_model_instead_of_pulling_it(
        monkeypatch: pytest.MonkeyPatch) -> None:
    from app.engine.data_engine import engine as data_engine

    monkeypatch.setattr("app.core.nlp.model_installed", lambda name: False)
    with monkeypatch.context() as patch:
        patch.setattr(settings, "presidio_enabled", True)
        status = data_engine.presidio_status
        result = data_engine.presidio_scan("phone 13800138000 email test@example.com")
        assert result == [], "拿不到模型就不该给出运行时识别结果"
        assert status()["available"] is False
        assert status()["reason"] == f"model_missing:{settings.presidio_model}"
