from __future__ import annotations

from pathlib import Path

from core.manual_validation import build_manual_validation_plan
from core.source_logic_analysis import analyze_source_logic

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "source_logic_cases"
BLOCKED_VALIDATION_TERMS = ("brute force", "DoS", "credential theft")


def test_manual_validation_plan_is_available_and_safe():
    finding = analyze_source_logic(FIXTURE_ROOT).findings[0]
    plan = build_manual_validation_plan(finding)

    assert plan["objective"]
    assert plan["step_by_step"]
    assert plan["evidence_to_collect"]

    combined = str(plan)
    for term in BLOCKED_VALIDATION_TERMS:
        assert term.lower() not in combined.lower()
