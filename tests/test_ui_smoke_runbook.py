from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "ui-smoke-test-runbook.md"


def runbook_text() -> str:
    return RUNBOOK.read_text(encoding="utf-8").lower()


def test_ui_smoke_test_runbook_exists():
    assert RUNBOOK.is_file()


def test_runbook_mentions_streamlit_ui_command():
    assert "streamlit run ui/app.py" in runbook_text()


def test_runbook_mentions_safety_banner():
    assert "safety banner" in runbook_text()


def test_runbook_mentions_source_logic_analysis():
    text = runbook_text()

    assert "source code analysis" in text
    assert "logic analysis" in text


def test_runbook_mentions_validation_ready_finding_and_manual_validation():
    text = runbook_text()

    assert "validation-ready finding" in text
    assert "manual validation" in text


def test_runbook_mentions_no_secret_leakage():
    assert "no secret leakage" in runbook_text()
