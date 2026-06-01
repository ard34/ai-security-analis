from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SENSITIVE_PATTERNS = [
    re.compile(r"authorization\s*:\s*bearer", re.IGNORECASE),
    re.compile(r"\bcookie\s*[:=]", re.IGNORECASE),
    re.compile(r"\bpassword\s*[:=]", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key\s*[:=]", re.IGNORECASE),
    re.compile(r"\bsession[_-]?id\s*[:=]", re.IGNORECASE),
]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def lower(path: str) -> str:
    return text(path).lower()


def json_data(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def findings(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        found = list(data.get("findings", []))
        for value in data.values():
            found.extend(findings(value))
        return found
    if isinstance(data, list):
        found: list[dict[str, Any]] = []
        for value in data:
            found.extend(findings(value))
        return found
    return []


def test_release_candidate_docs_exist():
    assert (ROOT / "docs" / "release-notes.md").is_file()
    assert (ROOT / "docs" / "safety-review.md").is_file()
    assert (ROOT / "docs" / "known-limitations.md").is_file()


def test_release_candidate_project_structure_exists():
    for path in [
        "app",
        "ui",
        "core",
        "modules",
        "reporting",
        "storage",
        "tests",
        "docs",
        "samples",
        "data",
        "reports",
        "exports",
        "logs",
    ]:
        assert (ROOT / path).exists(), path
    for path in ["cli.py", "requirements.txt", "pyproject.toml", "README.md", ".env.example", ".gitignore"]:
        assert (ROOT / path).is_file(), path


def test_gitignore_excludes_runtime_generated_paths():
    ignored = lower(".gitignore")

    for item in [
        "data/*",
        "reports/*",
        "exports/*",
        "logs/*.jsonl",
        ".env",
        ".venv/",
        "venv/",
        "__pycache__/",
        ".pytest_cache/",
    ]:
        assert item in ignored


def test_readme_mentions_required_release_candidate_content():
    readme = lower("README.md")

    assert "authorized-only" in readme
    assert "type 1" in readme
    assert "type 2" in readme
    assert "manual validation" in readme
    assert "no exploit" in readme
    assert "brute force" in readme
    assert "dos" in readme
    assert "release candidate" in readme


def test_operator_sop_mentions_assessment_approval():
    sop = lower("docs/operator-sop.md")

    assert "approve assessment" in sop or "assessment approval" in sop
    assert "archive assessment" in sop


def test_safety_review_mentions_engine_and_redaction():
    safety = lower("docs/safety-review.md")

    assert "safe execution engine" in safety
    assert "secret redaction" in safety
    assert "report redaction" in safety
    assert "no autonomous exploitation" in safety


def test_acceptance_criteria_contains_required_validation_items():
    criteria = lower("docs/acceptance-criteria.md")

    assert "pytest -q" in criteria
    assert "out-of-scope target rejected" in criteria
    assert "type 2 requires approved assessment" in criteria


def test_release_notes_contains_version():
    assert "v0.3.0-rc1" in text("docs/release-notes.md")


def test_known_limitations_mentions_false_positive_and_negative_risk():
    limitations = lower("docs/known-limitations.md")

    assert "false positives" in limitations
    assert "false negatives" in limitations


def test_sample_scan_results_keep_findings_potential():
    all_findings: list[dict[str, Any]] = []
    for path in (ROOT / "samples").glob("*.json"):
        all_findings.extend(findings(json_data(path)))

    assert all_findings
    assert all(item.get("is_potential") is True for item in all_findings)


def test_docs_and_samples_do_not_contain_obvious_fake_secrets():
    paths = [*(ROOT / "docs").glob("*.md"), *(ROOT / "samples").glob("*")]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.is_file())

    for pattern in SENSITIVE_PATTERNS:
        assert not pattern.search(combined)
