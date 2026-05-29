from __future__ import annotations

import pytest

from core.risk import calculate_priority, normalize_confidence, normalize_severity, severity_to_score, validate_finding_risk


def test_normalize_severity_accepts_valid_values_case_insensitive() -> None:
    assert normalize_severity("HIGH") == "high"


def test_invalid_severity_rejected() -> None:
    with pytest.raises(ValueError):
        normalize_severity("urgent")


def test_normalize_confidence_accepts_valid_values_case_insensitive() -> None:
    assert normalize_confidence("Medium") == "medium"


def test_invalid_confidence_rejected() -> None:
    with pytest.raises(ValueError):
        normalize_confidence("certain")


def test_severity_to_score_is_consistent() -> None:
    assert severity_to_score("info") == 0
    assert severity_to_score("critical") == 4


def test_calculate_priority_combines_severity_and_confidence() -> None:
    assert calculate_priority("medium", "high") > calculate_priority("low", "high")
    assert calculate_priority("medium", "high") > calculate_priority("medium", "low")


def test_passive_finding_caps_high_severity_without_strong_evidence() -> None:
    risk = validate_finding_risk("critical", "high", passive=True)
    assert risk["severity"] == "medium"


def test_strong_evidence_can_keep_declared_severity() -> None:
    risk = validate_finding_risk("critical", "high", passive=True, strong_evidence=True)
    assert risk["severity"] == "critical"

