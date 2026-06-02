from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "ui-runtime-validation-supported-python.md"


def doc_text() -> str:
    return DOC.read_text(encoding="utf-8").lower()


def test_ui_runtime_validation_doc_exists():
    assert DOC.is_file()


def test_ui_runtime_validation_doc_mentions_supported_python():
    text = doc_text()

    assert "python 3.11-3.13" in text
    assert "streamlit dependency stack" in text


def test_ui_runtime_validation_doc_mentions_streamlit_command():
    assert "streamlit run ui/app.py" in doc_text()


def test_ui_runtime_validation_doc_mentions_fallback_for_python_315():
    text = doc_text()

    assert "python 3.15" in text
    assert "skipping unsupported ui dependencies" in text
    assert "python ui\\app.py" in text


def test_ui_runtime_validation_doc_mentions_guardrails():
    text = doc_text()

    assert "manually_confirmed" in text
    assert "domain safe-live actions remain gated" in text
    assert "no unexpected network action" in text
