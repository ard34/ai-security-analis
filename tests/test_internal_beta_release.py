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


def test_internal_beta_release_doc_exists():
    assert (ROOT / "docs" / "internal-beta-release.md").is_file()


def test_internal_beta_release_doc_mentions_required_topics():
    doc = lower("docs/internal-beta-release.md")

    assert "v0.3.0-beta1" in doc
    assert "authorized usage" in doc
    assert "type 1" in doc
    assert "type 2" in doc
    assert "safety model" in doc
    assert "known limitations" in doc


def test_release_notes_and_readme_reference_internal_beta():
    assert "v0.3.0-beta1" in lower("docs/release-notes.md")
    assert "internal beta" in lower("README.md")


def test_docs_mention_manual_validation_and_blocked_activity():
    docs = "\n".join(path.read_text(encoding="utf-8").lower() for path in (ROOT / "docs").glob("*.md"))

    assert "manual validation" in docs
    assert "no exploit" in docs or "exploit automation" in docs
    assert "brute force" in docs
    assert "dos" in docs


def test_docs_contain_no_fake_secrets():
    docs = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "docs").glob("*.md"))

    for pattern in SENSITIVE_PATTERNS:
        assert not pattern.search(docs)
