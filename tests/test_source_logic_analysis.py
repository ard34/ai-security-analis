from __future__ import annotations

from pathlib import Path

from core.source_logic_analysis import analyze_source_logic

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "source_logic_cases"


def test_source_logic_analyzer_finds_source_location_and_route():
    result = analyze_source_logic(FIXTURE_ROOT)

    assert result.findings
    assert any(finding.source_locations for finding in result.findings)
    assert any("/accounts/<account_id>" in finding.affected_routes for finding in result.findings)
    assert any("get_account" in finding.affected_functions for finding in result.findings)


def test_source_logic_analyzer_explains_root_cause_and_status():
    result = analyze_source_logic(FIXTURE_ROOT)

    titles = [finding.title.lower() for finding in result.findings]
    assert any("broken access control" in title for title in titles)
    assert any("missing authentication" in title for title in titles)
    assert any("mass assignment" in title for title in titles)
    assert any("file handling" in title for title in titles)
    assert any("url fetch" in title for title in titles)
    assert all(finding.root_cause for finding in result.findings)
    assert all(finding.validation_status == "validation_ready" for finding in result.findings)
    assert not any(finding.validation_status == "manually_confirmed" for finding in result.findings)
