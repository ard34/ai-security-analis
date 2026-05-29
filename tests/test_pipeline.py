from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from core.models import Finding, ScanSession
from core.pipeline import run_dummy_pipeline
from core.policies import PolicyError


def test_pipeline_accepts_authorized_exact_domain() -> None:
    session = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert session.status == "success"
    assert session.target.normalized_target == "example.com"


def test_pipeline_accepts_authorized_subdomain() -> None:
    session = run_dummy_pipeline("app.example.com", allowed_domains=["example.com"])

    assert session.status == "success"
    assert session.target.normalized_target == "app.example.com"


def test_pipeline_rejects_out_of_scope_domain() -> None:
    session = run_dummy_pipeline("evil.com", allowed_domains=["example.com"])

    assert session.status == "rejected"
    assert session.findings == []
    assert session.assets == []


def test_pipeline_rejects_lookalike_domain() -> None:
    session = run_dummy_pipeline("example.com.evil.com", allowed_domains=["example.com"])

    assert session.status == "rejected"
    assert session.findings == []


def test_pipeline_rejects_invalid_scan_mode() -> None:
    with pytest.raises(PolicyError):
        run_dummy_pipeline("example.com", allowed_domains=["example.com"], scan_mode="aggressive")


def test_pipeline_generates_scan_id() -> None:
    session = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert session.scan_id


def test_pipeline_generates_success_status_for_valid_target() -> None:
    session = run_dummy_pipeline("example.com", allowed_domains=["example.com"], scan_mode="safe")

    assert session.status == "success"


def test_pipeline_generates_rejected_status_for_out_of_scope_target() -> None:
    session = run_dummy_pipeline("evil.com", allowed_domains=["example.com"], scan_mode="safe")

    assert session.status == "rejected"


def test_pipeline_generates_findings_from_security_headers_analyzer() -> None:
    session = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert session.findings
    assert all(isinstance(finding, Finding) for finding in session.findings)
    assert {finding.module for finding in session.findings} == {"security_headers"}


def test_all_findings_are_potential() -> None:
    session = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert all(finding.is_potential is True for finding in session.findings)


def test_commands_executed_is_empty_for_dummy_pipeline() -> None:
    session = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert session.audit_log["commands_executed"] == []
    assert all(result.commands_executed == [] for result in session.tool_results)


def test_pipeline_does_not_perform_network_requests() -> None:
    with patch("socket.create_connection", side_effect=AssertionError("network request attempted")):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network request attempted")):
            session = run_dummy_pipeline("app.example.com", allowed_domains=["example.com"])

    assert session.status == "success"
    assert session.audit_log["commands_executed"] == []


def test_audit_log_has_required_fields() -> None:
    session = run_dummy_pipeline("app.example.com", allowed_domains=["example.com"], scan_mode="standard")
    audit = session.audit_log

    assert audit["target"] == "app.example.com"
    assert audit["scan_mode"] == "standard"
    assert audit["modules_enabled"] == ["security_headers"]
    assert audit["commands_executed"] == []
    assert audit["errors"] == []
    assert audit["findings_generated"] == len(session.findings)


def test_started_at_and_ended_at_are_available() -> None:
    session = run_dummy_pipeline("example.com", allowed_domains=["example.com"])

    assert session.started_at
    assert session.ended_at


def test_allowed_scope_is_stored_in_result() -> None:
    session = run_dummy_pipeline("example.com", allowed_domains=["example.com"], allowed_ips=["8.8.8.8"])

    assert session.allowed_scope == {"allowed_domains": ["example.com"], "allowed_ips": ["8.8.8.8"]}
    assert session.audit_log["allowed_scope"] == session.allowed_scope
