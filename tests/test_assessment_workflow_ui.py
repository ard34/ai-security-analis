from __future__ import annotations

import html

from core.assessment import Assessment
from ui.app import (
    assessment_scope_to_display_rows,
    build_assessment_form_state,
    can_approve_assessment_from_ui,
    can_archive_assessment_from_ui,
    can_run_domain_scan_for_assessment,
    filter_scan_history_by_assessment,
    sanitize_assessment_display_data,
    summarize_assessment_project,
)


def valid_draft() -> Assessment:
    return build_assessment_form_state(
        name="Internal preprod",
        target="app.example.com",
        allowed_domains="example.com",
        owner_operator="Security Team",
        authorization_note="Approved ticket SEC-123",
        environment="pre-production",
    )


def test_assessment_draft_can_be_created_from_form_state():
    assessment = valid_draft()

    assert assessment.name == "Internal preprod"
    assert assessment.status == "draft"
    assert assessment.approved is False
    assert assessment.allowed_targets == ["example.com", "app.example.com"]
    assert assessment.owner_operator == "Security Team"
    assert assessment.environment == "pre-production"


def test_assessment_approved_only_when_minimum_data_valid():
    assessment = valid_draft()

    assert can_approve_assessment_from_ui(assessment) is True
    assessment.approve()
    assert assessment.status == "approved"
    assert assessment.approved is True

    missing_note = build_assessment_form_state(
        name="Internal preprod",
        target="app.example.com",
        allowed_domains="example.com",
        owner_operator="Security Team",
        authorization_note="",
    )
    assert can_approve_assessment_from_ui(missing_note) is False


def test_assessment_archived_cannot_be_used_for_scan():
    assessment = valid_draft().approve().archive()

    assert assessment.status == "archived"
    assert can_archive_assessment_from_ui(assessment) is False
    assert (
        can_run_domain_scan_for_assessment(
            assessment=assessment,
            target="app.example.com",
            confirmed=True,
            safe_live=True,
            allow_network=True,
            audit_log_path="logs/audit.jsonl",
        )
        is False
    )


def test_target_out_of_scope_cannot_be_used():
    assessment = valid_draft().approve()

    assert (
        can_run_domain_scan_for_assessment(
            assessment=assessment,
            target="outside.example.net",
            confirmed=True,
            safe_live=True,
            allow_network=True,
            audit_log_path="logs/audit.jsonl",
        )
        is False
    )


def test_safe_live_button_stays_disabled_if_assessment_unapproved():
    assert (
        can_run_domain_scan_for_assessment(
            assessment=valid_draft(),
            target="app.example.com",
            confirmed=True,
            safe_live=True,
            allow_network=True,
            audit_log_path="logs/audit.jsonl",
        )
        is False
    )


def test_authorization_note_display_is_safe_and_html_escaped():
    assessment = build_assessment_form_state(
        name="Internal preprod",
        target="app.example.com",
        allowed_domains="example.com",
        owner_operator="Security Team",
        authorization_note="<b>ticket</b>",
    )

    summary = summarize_assessment_project(assessment)

    assert summary["authorization_note"] == html.escape("<b>ticket</b>", quote=True)


def test_sensitive_value_redacted_from_assessment_display():
    assessment = build_assessment_form_state(
        name="Internal preprod",
        target="app.example.com",
        allowed_domains="example.com",
        owner_operator="Security Team",
        authorization_note="Authorization: Bearer verysecret",
    )

    display = sanitize_assessment_display_data(summarize_assessment_project(assessment))

    assert "verysecret" not in str(display)
    assert "[REDACTED]" in str(display)


def test_scope_rows_and_scan_history_helpers_are_import_safe():
    assessment = valid_draft().approve()
    history = [
        {"id": "scan_1", "target": "app.example.com", "workflow": "type2_domain"},
        {"id": "scan_2", "target": "outside.example.net", "workflow": "type2_domain"},
        {"id": "scan_3", "target": "api.example.com", "assessment_name": "Internal preprod"},
    ]

    rows = assessment_scope_to_display_rows(assessment)
    filtered = filter_scan_history_by_assessment(history, assessment)

    assert {"type": "domain", "value": "example.com"} in rows
    assert [row["id"] for row in filtered] == ["scan_1", "scan_3"]
