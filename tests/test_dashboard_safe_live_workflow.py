from __future__ import annotations

import inspect

import ui.app
from core.assessment import Assessment
from core.models import Evidence, ScanResult
from core.policies import DomainRunPolicy
from ui.app import (
    build_dashboard_live_config,
    can_export_dashboard_result,
    can_run_safe_live_from_dashboard,
    dashboard_result_exports,
    run_safe_live_from_dashboard,
    sanitize_dashboard_display_data,
    safe_live_gate_reasons,
    summarize_assessment_status,
)


def approved_assessment() -> Assessment:
    return Assessment("internal", ["example.com"]).approve()


def test_run_button_disabled_if_assessment_not_approved():
    assessment = Assessment("internal", ["example.com"])

    assert (
        can_run_safe_live_from_dashboard(
            assessment=assessment,
            target="example.com",
            confirmed=True,
            safe_live=True,
            allow_network=True,
            audit_log_path="logs/audit.jsonl",
        )
        is False
    )
    assert "assessment is not approved" in safe_live_gate_reasons(
        assessment=assessment,
        target="example.com",
        confirmed=True,
        safe_live=True,
        allow_network=True,
        audit_log_path="logs/audit.jsonl",
    )


def test_run_button_disabled_if_target_out_of_scope():
    assert (
        can_run_safe_live_from_dashboard(
            assessment=approved_assessment(),
            target="outside.example.net",
            confirmed=True,
            safe_live=True,
            allow_network=True,
            audit_log_path="logs/audit.jsonl",
        )
        is False
    )


def test_run_button_disabled_if_confirmation_missing():
    assert (
        can_run_safe_live_from_dashboard(
            assessment=approved_assessment(),
            target="example.com",
            confirmed=False,
            safe_live=True,
            allow_network=True,
            audit_log_path="logs/audit.jsonl",
        )
        is False
    )


def test_run_button_disabled_if_allow_network_false():
    assert (
        can_run_safe_live_from_dashboard(
            assessment=approved_assessment(),
            target="example.com",
            confirmed=True,
            safe_live=True,
            allow_network=False,
            audit_log_path="logs/audit.jsonl",
        )
        is False
    )


def test_run_button_disabled_if_safe_live_false():
    assert (
        can_run_safe_live_from_dashboard(
            assessment=approved_assessment(),
            target="example.com",
            confirmed=True,
            safe_live=False,
            allow_network=True,
            audit_log_path="logs/audit.jsonl",
        )
        is False
    )


def test_dashboard_helper_does_not_run_network_directly(monkeypatch):
    calls: list[tuple[str, Assessment, DomainRunPolicy]] = []

    def fake_pipeline(target: str, assessment: Assessment, policy: DomainRunPolicy) -> ScanResult:
        calls.append((target, assessment, policy))
        return ScanResult(target=target, workflow="type2_domain")

    monkeypatch.setattr(ui.app, "run_domain_assessment", fake_pipeline)
    policy = build_dashboard_live_config(
        safe_live=True,
        allow_network=True,
        confirmed=True,
        audit_log_path="logs/audit.jsonl",
    )

    result = run_safe_live_from_dashboard(target="example.com", assessment=approved_assessment(), policy=policy)

    assert result.workflow == "type2_domain"
    assert calls and calls[0][0] == "example.com"
    source = inspect.getsource(ui.app)
    assert "resolve_a_aaaa(" not in source
    assert "fetch_security_headers(" not in source
    assert "fingerprint_http(" not in source
    assert "fetch_robots_and_sitemap(" not in source
    assert "subprocess" not in source
    assert "os.system" not in source
    assert "pickle" not in source


def test_export_button_only_active_if_last_scan_result_available():
    assert can_export_dashboard_result(None) is False
    result = ScanResult(target="example.com", workflow="type2_domain")
    assert can_export_dashboard_result(result) is True
    exports = dashboard_result_exports(result)
    assert set(exports) == {"json", "html", "pdf"}


def test_sensitive_value_redacted_from_display_and_exports():
    result = ScanResult(target="example.com", workflow="type2_domain")
    result.evidence.append(
        Evidence(
            source="headers",
            content="Authorization: Bearer abc123",
            metadata={"api_key": "secret-value", "nested": {"password": "pw123"}},
        )
    )
    result.audit_events.append({"event": "x", "cookie": "session=abc", "message": "token=abc123"})

    display = sanitize_dashboard_display_data(result)
    display_text = str(display)
    assert "abc123" not in display_text
    assert "secret-value" not in display_text
    assert "pw123" not in display_text
    assert "session=abc" not in display_text
    assert "[REDACTED]" in display_text

    exports = dashboard_result_exports(result)
    assert "abc123" not in str(exports)
    assert "secret-value" not in str(exports)


def test_helpers_import_safe_and_status_summary():
    status = summarize_assessment_status(approved_assessment(), "sub.example.com", authorization_note="token=abc")

    assert status["approved"] is True
    assert status["target_in_scope"] is True
    assert status["allowed_scope"] == ["example.com"]
    assert status["authorization_note"] == "token=[REDACTED]"
