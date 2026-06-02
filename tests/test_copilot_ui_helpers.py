from __future__ import annotations

from pathlib import Path

from core.pipeline_source import run_source_assessment
from ui.app import (
    build_finding_detail_view_model,
    build_sidebar_navigation_state,
    build_source_analysis_form_state,
    can_export_from_ui,
    can_run_source_logic_analysis_from_ui,
    findings_to_workspace_rows,
    get_selected_finding,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "source_logic_cases"


def test_sidebar_navigation_state_valid():
    state = build_sidebar_navigation_state("Reports")

    assert state["active"] == "Reports"
    assert "Source Code Analysis" in state["items"]
    assert "Settings/Safety" in state["items"]


def test_source_analysis_form_state_and_run_gate():
    state = build_source_analysis_form_state(str(FIXTURE_ROOT), logic_analysis=True)

    assert state["source_path"] == str(FIXTURE_ROOT)
    assert state["logic_analysis"] is True
    assert state["local_only"] is True
    assert state["can_run"] is True
    assert can_run_source_logic_analysis_from_ui("") is False


def test_export_only_active_if_scan_result_available():
    assert can_export_from_ui(None) is False
    assert can_export_from_ui(run_source_assessment(FIXTURE_ROOT)) is True


def test_finding_workspace_rows_and_detail_model():
    result = run_source_assessment(FIXTURE_ROOT, logic_analysis=True)
    rows = findings_to_workspace_rows(result)
    finding = get_selected_finding(result, 0)
    detail = build_finding_detail_view_model(finding)

    assert rows
    assert detail["selected"] is True
    assert detail["root_cause"]
    assert detail["manual_validation_steps"]
