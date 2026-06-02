from __future__ import annotations

from pathlib import Path

from core.pipeline_source import run_source_assessment
from reporting.html_report import render_html_report
from reporting.pdf_report import render_pdf_report

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "source_logic_cases"


def test_report_shows_validation_ready_sections():
    result = run_source_assessment(FIXTURE_ROOT, logic_analysis=True)
    html = render_html_report(result)

    assert "Validation-ready findings are logic-derived" in html
    assert "Manual validation steps" in html
    assert "False positive checks" in html
    assert "Remediation" in html


def test_pdf_report_handles_validation_ready_findings():
    result = run_source_assessment(FIXTURE_ROOT, logic_analysis=True)

    assert render_pdf_report(result)
