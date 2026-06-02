from __future__ import annotations

import pytest

from core.finding_validation import (
    build_validation_status_options,
    can_mark_finding_manually_confirmed,
    sanitize_validation_note,
    update_finding_validation_status,
)
from core.models import Finding


def test_manually_confirmed_cannot_be_set_by_automation():
    with pytest.raises(ValueError):
        update_finding_validation_status(
            Finding(title="x"),
            status="manually_confirmed",
            reviewer="r",
            note="n",
            evidence_note="e",
            actor="ai",
        )


def test_manually_confirmed_requires_reviewer_note_and_evidence():
    finding = Finding(title="x")

    assert can_mark_finding_manually_confirmed(reviewer="", note="n", evidence_note="e") is False
    with pytest.raises(ValueError):
        update_finding_validation_status(finding, status="manually_confirmed", reviewer="", note="n", evidence_note="e")

    updated = update_finding_validation_status(
        finding,
        status="manually_confirmed",
        reviewer="operator",
        note="manual evidence reviewed",
        evidence_note="request and response attached",
    )

    assert updated.validation_status == "manually_confirmed"
    assert updated.metadata["validation_update"]["timestamp"]


def test_false_positive_and_accepted_risk_require_note():
    finding = Finding(title="x")

    with pytest.raises(ValueError):
        update_finding_validation_status(finding, status="false_positive")

    update_finding_validation_status(finding, status="false_positive", note="guard exists in middleware")
    assert finding.validation_status == "false_positive"

    update_finding_validation_status(finding, status="accepted_risk", note="approved by owner")
    assert finding.validation_status == "accepted_risk"


def test_validation_note_redacts_secret_and_invalid_status_rejected():
    assert "secret-value" not in sanitize_validation_note("api_key=secret-value")
    with pytest.raises(ValueError):
        update_finding_validation_status(Finding(title="x"), status="bad-status")
    assert "needs_more_review" in build_validation_status_options()
