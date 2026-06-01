from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SENSITIVE_PATTERNS = [
    re.compile(r"authorization\s*:\s*bearer", re.IGNORECASE),
    re.compile(r"\bcookie\s*[:=]", re.IGNORECASE),
    re.compile(r"\bpassword\s*[:=]", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key\s*[:=]", re.IGNORECASE),
    re.compile(r"\bsession[_-]?id\s*[:=]", re.IGNORECASE),
]


def lower(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8").lower()


def test_pilot_plan_and_feedback_template_exist():
    assert (ROOT / "docs" / "internal-beta-pilot-plan.md").is_file()
    assert (ROOT / "docs" / "internal-beta-feedback-template.md").is_file()


def test_pilot_plan_mentions_required_topics():
    plan = lower("docs/internal-beta-pilot-plan.md")

    assert "authorized-only" in plan
    assert "type 1" in plan
    assert "type 2" in plan
    assert "stop conditions" in plan
    assert "audit log" in plan


def test_feedback_template_contains_required_fields():
    template = lower("docs/internal-beta-feedback-template.md")

    assert "false positives" in template
    assert "false negatives" in template
    assert "safety concerns" in template
    assert "severity" in template


def test_pilot_docs_do_not_contain_fake_secrets():
    combined = lower("docs/internal-beta-pilot-plan.md") + "\n" + lower("docs/internal-beta-feedback-template.md")

    for pattern in SENSITIVE_PATTERNS:
        assert not pattern.search(combined)
