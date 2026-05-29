from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from core.models import Finding, ScanSession
from core.pipeline import run_dummy_pipeline


def test_pipeline_rejects_out_of_scope_target() -> None:
    with pytest.raises(ValueError, match="Target rejected by scope validation"):
        run_dummy_pipeline("evil.com", allowed_domains=["example.com"], scan_mode="strict")


def test_pipeline_accepts_authorized_target() -> None:
    session = run_dummy_pipeline("https://app.example.com", allowed_domains=["example.com"], scan_mode="strict")

    assert isinstance(session, ScanSession)
    assert session.target.normalized_target == "app.example.com"
    assert session.scan_mode == "strict"


def test_pipeline_generates_normalized_assets_endpoints_and_findings() -> None:
    session = run_dummy_pipeline("app.example.com", allowed_domains=["example.com"], scan_mode="safe")

    assert session.assets
    assert session.assets[0].value == "https://app.example.com"
    assert session.endpoints
    assert session.endpoints[0].url == "https://app.example.com/login"
    assert session.findings
    assert all(isinstance(finding, Finding) for finding in session.findings)
    assert all(finding.is_potential for finding in session.findings)
    assert {finding.module for finding in session.findings} == {"security_headers"}


def test_pipeline_includes_audit_log_fields() -> None:
    session = run_dummy_pipeline("app.example.com", allowed_domains=["example.com"], scan_mode="standard")
    audit = session.audit_log

    assert audit["scan_id"] == session.scan_id
    assert audit["target"] == "app.example.com"
    assert audit["authorized_scope"]["allowed_domains"] == ["example.com"]
    assert audit["scan_mode"] == "standard"
    assert audit["modules_enabled"] == ["dummy_asset_generation", "security_headers"]
    assert audit["commands_executed"] == []
    assert audit["errors"] == []
    assert audit["findings_generated"] == len(session.findings)
    assert audit["start_time"]
    assert audit["end_time"]


def test_pipeline_does_not_perform_network_requests() -> None:
    with patch("socket.create_connection", side_effect=AssertionError("network request attempted")):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network request attempted")):
            session = run_dummy_pipeline("app.example.com", allowed_domains=["example.com"], scan_mode="strict")

    assert session.audit_log["commands_executed"] == []

