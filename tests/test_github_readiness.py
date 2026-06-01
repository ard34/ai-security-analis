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


def test_github_readiness_docs_exist():
    assert (ROOT / "docs" / "github-readiness-checklist.md").is_file()
    assert (ROOT / "docs" / "internal-beta-feedback-loop.md").is_file()


def test_issue_templates_exist():
    for name in [
        "bug-report.md",
        "safety-concern.md",
        "false-positive.md",
        "false-negative.md",
        "ux-feedback.md",
    ]:
        assert (ROOT / "docs" / "issue-templates" / name).is_file()


def test_github_readiness_checklist_mentions_required_items():
    checklist = lower("docs/github-readiness-checklist.md")

    assert "pytest" in checklist
    assert "no `.env`" in checklist
    assert "no secrets" in checklist
    assert "runtime logs" in checklist
    assert "v0.3.0-beta1" in checklist


def test_feedback_loop_mentions_required_items():
    feedback = lower("docs/internal-beta-feedback-loop.md")

    assert "authorized-only" in feedback
    assert "type 1" in feedback
    assert "type 2" in feedback
    assert "stop conditions" in feedback


def test_safety_concern_template_mentions_stop_risks():
    safety = lower("docs/issue-templates/safety-concern.md")

    assert "unclear scope" in safety
    assert "unexpected network behavior" in safety


def test_issue_templates_contain_no_fake_secrets():
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "docs" / "issue-templates").glob("*.md")
    )

    for pattern in SENSITIVE_PATTERNS:
        assert not pattern.search(combined)


def test_readme_still_mentions_core_safety_language():
    readme = lower("README.md")

    assert "authorized-only" in readme
    assert "manual validation" in readme
    assert "no exploit" in readme
    assert "brute force" in readme
    assert "dos" in readme
