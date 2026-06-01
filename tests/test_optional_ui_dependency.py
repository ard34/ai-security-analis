from __future__ import annotations

import builtins
import importlib
import sys

import pytest


def block_streamlit_import(monkeypatch: pytest.MonkeyPatch) -> None:
    original_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "streamlit" or name.startswith("streamlit."):
            raise ImportError("streamlit is intentionally unavailable in core mode")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.delitem(sys.modules, "streamlit", raising=False)


def test_core_imports_do_not_require_streamlit(monkeypatch: pytest.MonkeyPatch):
    block_streamlit_import(monkeypatch)

    for module_name in [
        "core.assessment",
        "core.pipeline_domain",
        "core.pipeline_source",
        "reporting.html_report",
        "reporting.pdf_report",
        "storage.database",
        "storage.json_io",
        "ui.chat",
        "ui.app",
        "app.dashboard",
    ]:
        importlib.import_module(module_name)


def test_streamlit_entrypoint_is_optional(monkeypatch: pytest.MonkeyPatch):
    block_streamlit_import(monkeypatch)

    ui_app = importlib.import_module("ui.app")

    assert ui_app.render_streamlit() is None


def test_cli_help_runs_without_streamlit(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    block_streamlit_import(monkeypatch)
    cli = importlib.import_module("cli")

    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])

    assert exc.value.code == 0
    assert "ai-security-analyst" in capsys.readouterr().out
