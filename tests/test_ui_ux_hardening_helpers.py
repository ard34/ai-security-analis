from __future__ import annotations

from pathlib import Path

from core.models import ScanResult
from ui.app import (
    build_export_unavailable_reason,
    build_manual_confirmation_warning,
    build_no_finding_selected_message,
    build_no_scan_selected_message,
    build_source_analysis_disabled_reason,
    build_streamlit_missing_message,
)


def test_no_scan_selected_message_clear():
    message = build_no_scan_selected_message()

    assert "No scan is selected" in message
    assert "load a saved scan" in message


def test_no_finding_selected_message_clear():
    message = build_no_finding_selected_message()

    assert "No finding is selected" in message
    assert "validation-ready finding" in message


def test_export_unavailable_reason_clear():
    assert "unavailable" in build_export_unavailable_reason(None)
    assert build_export_unavailable_reason(ScanResult(target="x", workflow="w")) == ""


def test_manual_confirmation_warning_clear():
    warning = build_manual_confirmation_warning()

    assert "manually_confirmed" in warning
    assert "authorized manual validation" in warning
    assert "evidence" in warning


def test_source_analysis_disabled_reason_clear():
    assert "local source path" in build_source_analysis_disabled_reason("")
    assert "does not exist" in build_source_analysis_disabled_reason("missing/path")
    assert build_source_analysis_disabled_reason(str(Path("."))) == ""


def test_streamlit_missing_message_points_to_optional_ui_dependency():
    message = build_streamlit_missing_message()

    assert "Streamlit is optional" in message
    assert "requirements-ui.txt" in message
