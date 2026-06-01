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


def test_controlled_beta_docs_exist():
    assert (ROOT / "docs" / "internal-beta-pilot-execution.md").is_file()
    assert (ROOT / "docs" / "internal-beta-feedback-loop.md").is_file()
    assert (ROOT / "docs" / "internal-beta-pilot-runbook.md").is_file()
    assert (ROOT / "docs" / "small-bugfix-policy.md").is_file()


def test_feedback_templates_exist():
    folder = ROOT / "docs" / "feedback-templates"
    assert folder.is_dir()
    for name in [
        "bug-report.md",
        "ux-issue.md",
        "false-positive.md",
        "false-negative.md",
        "safety-concern.md",
        "report-review.md",
        "audit-log-review.md",
    ]:
        assert (folder / name).is_file()


def test_pilot_execution_mentions_required_controls():
    doc = lower("docs/internal-beta-pilot-execution.md")

    assert "1-3 internal tester" in doc
    assert "authorization" in doc
    assert "stop conditions" in doc
    assert "type 1" in doc
    assert "type 2" in doc


def test_feedback_loop_mentions_feedback_categories():
    doc = lower("docs/internal-beta-feedback-loop.md")

    assert "false positive" in doc
    assert "false negative" in doc
    assert "safety concern" in doc


def test_runbook_mentions_required_workflows():
    doc = lower("docs/internal-beta-pilot-runbook.md")

    assert "type 1" in doc
    assert "type 2" in doc
    assert "scan-domain --target example.com" in doc
    assert "rejected because required gated args are missing" in doc


def test_small_bugfix_policy_blocks_offensive_features():
    doc = lower("docs/small-bugfix-policy.md")

    assert "what is not allowed" in doc
    assert "exploit automation" in doc
    assert "brute force tooling" in doc
    assert "dos testing" in doc
    assert "active scanner integration" in doc


def test_docs_and_templates_contain_no_fake_secrets():
    paths = [
        ROOT / "docs" / "internal-beta-pilot-execution.md",
        ROOT / "docs" / "internal-beta-feedback-loop.md",
        ROOT / "docs" / "internal-beta-pilot-runbook.md",
        ROOT / "docs" / "small-bugfix-policy.md",
        *(ROOT / "docs" / "feedback-templates").glob("*.md"),
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)

    for pattern in SENSITIVE_PATTERNS:
        assert not pattern.search(combined)


def test_readme_still_mentions_core_safety_language():
    readme = lower("README.md")

    assert "authorized-only" in readme
    assert "manual validation" in readme
    assert "no exploit" in readme
    assert "brute force" in readme
    assert "dos" in readme
