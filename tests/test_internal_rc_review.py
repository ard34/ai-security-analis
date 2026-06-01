from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def lower(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8").lower()


def test_internal_rc_review_doc_exists():
    assert (ROOT / "docs" / "internal-rc-review.md").is_file()


def test_internal_rc_review_mentions_required_topics():
    review = lower("docs/internal-rc-review.md")

    assert "type 1" in review
    assert "type 2" in review
    assert "safety boundary" in review
    assert "manual validation" in review
    assert "approved assessment" in review
    assert "audit log" in review
    assert "no exploit" in review
    assert "brute force" in review
    assert "dos" in review


def test_existing_release_docs_still_exist():
    assert (ROOT / "docs" / "acceptance-criteria.md").is_file()
    assert (ROOT / "docs" / "release-notes.md").is_file()
