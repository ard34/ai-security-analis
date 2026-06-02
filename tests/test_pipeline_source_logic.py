from __future__ import annotations

from pathlib import Path

from core.pipeline_source import run_source_assessment

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "source_logic_cases"


def test_pipeline_source_logic_analysis_adds_validation_ready_findings():
    result = run_source_assessment(FIXTURE_ROOT, logic_analysis=True)

    assert result.workflow == "type1_source"
    assert result.metadata["source_logic_analysis"]
    assert any(finding.validation_status == "validation_ready" for finding in result.findings)
    assert all(finding.validation_status != "manually_confirmed" for finding in result.findings)


def test_pipeline_source_logic_analysis_is_opt_in():
    result = run_source_assessment(FIXTURE_ROOT)

    assert "source_logic_analysis" not in result.metadata
