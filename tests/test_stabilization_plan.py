from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def lower(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8").lower()


def test_stabilization_plan_exists():
    assert (ROOT / "docs" / "bugfix-stabilization-plan.md").is_file()


def test_stabilization_plan_mentions_required_topics():
    plan = lower("docs/bugfix-stabilization-plan.md")

    assert "blocker" in plan
    assert "safety regression" in plan
    assert "what must be deferred" in plan
    assert "pytest" in plan
    assert "type 1" in plan
    assert "type 2" in plan


def test_stabilization_plan_mentions_deferred_items_without_recommending_them():
    plan = lower("docs/bugfix-stabilization-plan.md")

    assert "exploit automation" in plan
    assert "active scanner integration" in plan
    assert "brute force tooling" in plan
    assert "aggressive crawling" in plan
    assert "credentialed testing without future guarded design" in plan
    assert "auth bypass tooling" in plan
    assert "malware, reverse shell, or persistence" in plan
    assert "must be deferred" in plan


def test_existing_docs_exist():
    assert (ROOT / "docs" / "known-limitations.md").is_file()
    assert (ROOT / "docs" / "acceptance-criteria.md").is_file()


def test_docs_do_not_suggest_adding_unsafe_features():
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in (ROOT / "docs").glob("*.md"))

    assert "add exploit" not in combined
    assert "implement exploit" not in combined
    assert "add brute force" not in combined
    assert "implement brute force" not in combined
    assert "add dos" not in combined
    assert "implement dos" not in combined
