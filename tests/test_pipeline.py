from __future__ import annotations

import json
import socket

import pytest

from core.models import Finding
from core.pipeline import run_dummy_pipeline
from core.policies import PolicyError


def test_pipeline_accepts_authorized_exact_domain() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert result["status"] == "success"
    assert result["normalized_target"] == "example.com"


def test_pipeline_accepts_authorized_subdomain() -> None:
    result = run_dummy_pipeline("app.example.com", allowed_domains=["example.com"])

    assert result["status"] == "success"
    assert result["normalized_target"] == "app.example.com"


def test_pipeline_rejects_out_of_scope_domain() -> None:
    result = run_dummy_pipeline("evil.com", allowed_domains=["example.com"])

    assert result["status"] == "rejected"
    assert result["findings"] == []
    assert result["reason"]


def test_pipeline_rejects_lookalike_domain() -> None:
    result = run_dummy_pipeline("example.com.evil.com", allowed_domains=["example.com"])

    assert result["status"] == "rejected"
    assert result["findings"] == []


def test_pipeline_rejects_invalid_scan_mode() -> None:
    with pytest.raises(PolicyError):
        run_dummy_pipeline("example.com", allowed_domains=["example.com"], scan_mode="aggressive")


def test_pipeline_generates_scan_id() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert result["scan_id"]


def test_pipeline_generates_success_status_for_valid_target() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"], scan_mode="safe")

    assert result["status"] == "success"


def test_pipeline_generates_rejected_status_for_out_of_scope_target() -> None:
    result = run_dummy_pipeline("evil.com", allowed_domains=["example.com"], scan_mode="safe")

    assert result["status"] == "rejected"


def test_pipeline_generates_findings_from_security_headers_analyzer() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert result["findings"]
    assert all(isinstance(finding, Finding) for finding in result["findings"])
    assert {finding.module for finding in result["findings"]} == {"security_headers"}


def test_all_findings_are_potential() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert all(finding.is_potential is True for finding in result["findings"])


def test_commands_executed_is_empty_for_dummy_pipeline() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert result["audit_log"]["commands_executed"] == []


def test_pipeline_does_not_use_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Network access is not allowed in dummy pipeline")

    monkeypatch.setattr(socket, "socket", fail_socket)

    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"], scan_mode="safe")

    assert result["status"] == "success"


def test_audit_log_has_required_fields() -> None:
    result = run_dummy_pipeline("app.example.com", allowed_domains=["example.com"], scan_mode="standard")
    audit = result["audit_log"]

    assert audit["target"] == "app.example.com"
    assert audit["scan_mode"] == "standard"
    assert audit["modules_enabled"] == ["security_headers"]
    assert audit["commands_executed"] == []
    assert audit["errors"] == []
    assert audit["findings_generated"] == len(result["findings"])


def test_started_at_and_ended_at_are_available() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert result["started_at"]
    assert result["ended_at"]


def test_allowed_scope_is_stored_in_result() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"], allowed_ips=["8.8.8.8"])

    assert result["allowed_scope"] == {"domains": ["example.com"], "ips": ["8.8.8.8"]}


def test_rejected_result_does_not_generate_findings() -> None:
    result = run_dummy_pipeline("evil.com", allowed_domains=["example.com"])

    assert result["status"] == "rejected"
    assert result["findings"] == []


def test_rejected_result_still_has_audit_log() -> None:
    result = run_dummy_pipeline("evil.com", allowed_domains=["example.com"])

    assert result["audit_log"]["target"] == "evil.com"
    assert result["audit_log"]["errors"]


def test_success_result_has_at_least_one_asset() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert result["assets"]


def test_success_result_has_at_least_one_endpoint() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert result["endpoints"]


def test_success_result_uses_security_headers_module() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert result["audit_log"]["modules_enabled"] == ["security_headers"]
    assert {finding.module for finding in result["findings"]} == {"security_headers"}


def test_success_result_has_audit_events() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert isinstance(result["audit_events"], list)
    assert result["audit_events"]


def test_rejected_result_has_audit_events() -> None:
    result = run_dummy_pipeline("evil.com", allowed_domains=["example.com"])

    assert isinstance(result["audit_events"], list)
    assert result["audit_events"]


def test_success_audit_events_include_scan_started() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert "scan_started" in {event["event_type"] for event in result["audit_events"]}


def test_success_audit_events_include_scan_completed() -> None:
    result = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert "scan_completed" in {event["event_type"] for event in result["audit_events"]}


def test_rejected_audit_events_include_scan_rejected() -> None:
    result = run_dummy_pipeline("evil.com", allowed_domains=["example.com"])

    assert "scan_rejected" in {event["event_type"] for event in result["audit_events"]}


def test_audit_events_do_not_contain_sensitive_metadata() -> None:
    result = run_dummy_pipeline("https://example.com?api_key=abc", allowed_domains=["example.com"])

    payload = json.dumps(result["audit_events"])

    assert "api_key=[REDACTED]" in payload
    assert "api_key=abc" not in payload
