from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SENSITIVE_PATTERNS = [
    re.compile(r"authorization:\s*bearer", re.IGNORECASE),
    re.compile(r"\bcookie\s*[:=]", re.IGNORECASE),
    re.compile(r"\bpassword\s*[:=]", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key\s*[:=]", re.IGNORECASE),
    re.compile(r"\btoken\s*[:=]", re.IGNORECASE),
]


def load_sample(name: str) -> dict[str, Any]:
    return json.loads((ROOT / "samples" / name).read_text(encoding="utf-8"))


def sample_json_files() -> list[Path]:
    return sorted((ROOT / "samples").glob("*.json"))


def finding_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        items = list(data.get("findings", []))
        for value in data.values():
            items.extend(finding_items(value))
        return items
    if isinstance(data, list):
        items: list[dict[str, Any]] = []
        for value in data:
            items.extend(finding_items(value))
        return items
    return []


def test_samples_and_docs_directories_exist():
    assert (ROOT / "samples").is_dir()
    assert (ROOT / "docs").is_dir()


def test_sample_assessment_approved_has_approved_status():
    assessment = load_sample("assessment-approved.json")

    assert assessment["approved"] is True
    assert assessment["status"] == "approved"


def test_sample_findings_are_all_potential():
    findings: list[dict[str, Any]] = []
    for path in sample_json_files():
        findings.extend(finding_items(json.loads(path.read_text(encoding="utf-8"))))

    assert findings
    assert all(item.get("is_potential") is True for item in findings)


def test_sample_data_contains_no_sensitive_values():
    sample_text = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "samples").iterdir() if path.is_file())

    for pattern in SENSITIVE_PATTERNS:
        assert not pattern.search(sample_text)


def test_docs_mention_authorized_only_usage():
    docs = "\n".join(path.read_text(encoding="utf-8").lower() for path in (ROOT / "docs").glob("*.md"))

    assert "authorized-only" in docs


def test_docs_mention_manual_validation():
    docs = "\n".join(path.read_text(encoding="utf-8").lower() for path in (ROOT / "docs").glob("*.md"))

    assert "manual validation" in docs


def test_docs_mention_no_exploit_brute_force_dos():
    docs = "\n".join(path.read_text(encoding="utf-8").lower() for path in (ROOT / "docs").glob("*.md"))

    assert "no exploit" in docs or "do not use the project for exploit" in docs
    assert "brute force" in docs
    assert "dos" in docs


def test_acceptance_criteria_file_exists():
    assert (ROOT / "docs" / "acceptance-criteria.md").is_file()
