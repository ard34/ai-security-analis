from __future__ import annotations

import inspect
import os
import socket
import subprocess

import pytest

import core.execution as execution_module
from core.execution import (
    ExecutionDecision,
    ExecutionPolicy,
    ExecutionState,
    KillSwitch,
    RateLimitConfig,
    SafeExecutionContext,
    ScanBudget,
    TimeoutConfig,
    check_kill_switch,
    check_scan_budget,
    create_execution_decision,
    enforce_scope_before_action,
    execution_decision_to_dict,
    is_dangerous_action,
    record_execution_audit_event,
    safe_execution_context_to_dict,
    sanitize_action_metadata,
    validate_execution_policy,
    validate_rate_limit_config,
    validate_scan_budget,
    validate_timeout_config,
    utc_now_iso,
)


def make_context(**overrides) -> SafeExecutionContext:
    payload = {
        "scan_id": "scan-001",
        "target": "example.com",
        "allowed_domains": ["example.com"],
    }
    payload.update(overrides)
    return SafeExecutionContext(**payload)


def test_default_scan_budget_valid() -> None:
    validate_scan_budget(ScanBudget())


def test_invalid_max_requests_rejected() -> None:
    with pytest.raises(ValueError):
        validate_scan_budget(ScanBudget(max_requests=0))


def test_invalid_max_duration_rejected() -> None:
    with pytest.raises(ValueError):
        validate_scan_budget(ScanBudget(max_duration_seconds=0))


def test_invalid_max_concurrency_rejected() -> None:
    with pytest.raises(ValueError):
        validate_scan_budget(ScanBudget(max_concurrency=0))


def test_invalid_max_errors_rejected() -> None:
    with pytest.raises(ValueError):
        validate_scan_budget(ScanBudget(max_errors=101))


def test_default_rate_limit_valid() -> None:
    validate_rate_limit_config(RateLimitConfig())


def test_invalid_requests_per_second_rejected() -> None:
    with pytest.raises(ValueError):
        validate_rate_limit_config(RateLimitConfig(requests_per_second=0))


def test_invalid_burst_rejected() -> None:
    with pytest.raises(ValueError):
        validate_rate_limit_config(RateLimitConfig(burst=0))


def test_default_timeout_valid() -> None:
    validate_timeout_config(TimeoutConfig())


def test_invalid_timeout_rejected() -> None:
    with pytest.raises(ValueError):
        validate_timeout_config(TimeoutConfig(connect_timeout=0))


def test_total_timeout_smaller_than_connect_or_read_rejected() -> None:
    with pytest.raises(ValueError):
        validate_timeout_config(TimeoutConfig(connect_timeout=5, read_timeout=10, total_timeout=4))


def test_default_execution_policy_valid() -> None:
    validate_execution_policy(ExecutionPolicy())


def test_allow_exploit_true_rejected() -> None:
    with pytest.raises(ValueError):
        validate_execution_policy(ExecutionPolicy(allow_exploit=True))


def test_allow_bruteforce_true_rejected() -> None:
    with pytest.raises(ValueError):
        validate_execution_policy(ExecutionPolicy(allow_bruteforce=True))


def test_allow_dos_true_rejected() -> None:
    with pytest.raises(ValueError):
        validate_execution_policy(ExecutionPolicy(allow_dos=True))


def test_allow_zap_active_true_rejected() -> None:
    with pytest.raises(ValueError):
        validate_execution_policy(ExecutionPolicy(allow_zap_active=True))


def test_unsafe_http_method_post_rejected() -> None:
    with pytest.raises(ValueError):
        validate_execution_policy(ExecutionPolicy(allowed_methods=("GET", "POST")))


def test_kill_switch_enabled_blocks_action() -> None:
    decision = check_kill_switch(KillSwitch(enabled=True, reason="stop"))

    assert decision is not None
    assert decision.allowed is False


def test_kill_switch_disabled_allows_continuing() -> None:
    assert check_kill_switch(KillSwitch()) is None


def test_budget_blocks_when_requests_exhausted() -> None:
    decision = check_scan_budget(ScanBudget(max_requests=1), ExecutionState(utc_now_iso(), requests_made=1), 0)

    assert decision is not None
    assert decision.allowed is False


def test_budget_blocks_when_duration_exceeded() -> None:
    decision = check_scan_budget(ScanBudget(max_duration_seconds=1), ExecutionState(utc_now_iso()), 1)

    assert decision is not None
    assert decision.allowed is False


def test_budget_blocks_when_concurrency_exceeded() -> None:
    decision = check_scan_budget(ScanBudget(max_concurrency=1), ExecutionState(utc_now_iso(), active_tasks=1), 0)

    assert decision is not None
    assert decision.allowed is False


def test_budget_blocks_when_errors_exceeded() -> None:
    decision = check_scan_budget(ScanBudget(max_errors=1), ExecutionState(utc_now_iso(), errors_seen=1), 0)

    assert decision is not None
    assert decision.allowed is False


def test_scope_enforcement_accepts_exact_authorized_domain() -> None:
    assert enforce_scope_before_action("example.com", ["example.com"]).allowed is True


def test_scope_enforcement_accepts_authorized_subdomain() -> None:
    assert enforce_scope_before_action("app.example.com", ["example.com"]).allowed is True


def test_scope_enforcement_rejects_out_of_scope_domain() -> None:
    assert enforce_scope_before_action("evil.com", ["example.com"]).allowed is False


def test_scope_enforcement_rejects_lookalike_domain() -> None:
    assert enforce_scope_before_action("example.com.evil.com", ["example.com"]).allowed is False


def test_scope_enforcement_rejects_localhost_by_default() -> None:
    assert enforce_scope_before_action("localhost", ["localhost"]).allowed is False


def test_scope_enforcement_accepts_explicitly_allowed_ip() -> None:
    assert enforce_scope_before_action("8.8.8.8", [], ["8.8.8.8"]).allowed is True


def test_metadata_sanitization_redacts_password() -> None:
    assert sanitize_action_metadata({"password": "secret"})["password"] == "[REDACTED]"


def test_metadata_sanitization_redacts_token() -> None:
    assert sanitize_action_metadata({"token": "abc"})["token"] == "[REDACTED]"


def test_metadata_sanitization_redacts_authorization() -> None:
    assert sanitize_action_metadata({"Authorization": "Bearer abc"})["Authorization"] == "[REDACTED]"


def test_metadata_sanitization_does_not_mutate_input() -> None:
    payload = {"token": "abc"}

    sanitize_action_metadata(payload)

    assert payload["token"] == "abc"


def test_dangerous_action_exploit_detected() -> None:
    assert is_dangerous_action("exploit")


def test_dangerous_action_brute_force_detected() -> None:
    assert is_dangerous_action("brute_force")


def test_dangerous_action_dos_detected() -> None:
    assert is_dangerous_action("ddos")


def test_network_http_get_blocked_by_default() -> None:
    decision = create_execution_decision("network:http_get", "example.com", make_context())

    assert decision.allowed is False
    assert "Network actions are disabled" in decision.reason


def test_network_dns_lookup_blocked_by_default() -> None:
    decision = create_execution_decision("network:dns_lookup", "example.com", make_context())

    assert decision.allowed is False
    assert "Network actions are disabled" in decision.reason


def test_tool_nmap_blocked_by_default() -> None:
    decision = create_execution_decision("tool:nmap", "example.com", make_context())

    assert decision.allowed is False
    assert "External tool actions are disabled" in decision.reason


def test_local_dummy_pipeline_allowed_if_scope_valid() -> None:
    decision = create_execution_decision("local:dummy_pipeline", "example.com", make_context())

    assert decision.allowed is True


def test_create_execution_decision_returns_audit_event() -> None:
    decision = create_execution_decision("local:dummy_pipeline", "example.com", make_context())

    assert decision.audit_event
    assert decision.audit_event["metadata"]["action"] == "local:dummy_pipeline"


def test_record_execution_audit_event_returns_sanitized_event() -> None:
    context = make_context()
    decision = ExecutionDecision(True, "ok", "local:dummy_pipeline", target="example.com")

    event = record_execution_audit_event("local:dummy_pipeline", decision, context, {"token": "abc"})

    assert event["metadata"]["metadata"]["token"] == "[REDACTED]"


def test_execution_decision_to_dict_returns_dict() -> None:
    decision = create_execution_decision("local:dummy_pipeline", "example.com", make_context())

    assert isinstance(execution_decision_to_dict(decision), dict)


def test_safe_execution_context_to_dict_redacts_metadata() -> None:
    payload = safe_execution_context_to_dict(make_context(metadata={"api_key": "abc"}))

    assert payload["metadata"]["api_key"] == "[REDACTED]"


def test_execution_engine_does_not_use_network(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in execution engine")

    monkeypatch.setattr(socket, "socket", fail_socket)
    monkeypatch.setattr(socket, "gethostbyname", fail_socket)

    decision = create_execution_decision("local:dummy_pipeline", "example.com", make_context())

    assert decision.allowed is True


def test_execution_engine_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in execution engine")

    monkeypatch.setattr(subprocess, "run", fail_run)

    decision = create_execution_decision("local:dummy_pipeline", "example.com", make_context())

    assert decision.allowed is True


def test_execution_engine_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in execution engine")

    monkeypatch.setattr(os, "system", fail_system)

    decision = create_execution_decision("local:dummy_pipeline", "example.com", make_context())

    assert decision.allowed is True


def test_execution_source_does_not_use_eval() -> None:
    assert "eval(" not in inspect.getsource(execution_module)


def test_execution_source_does_not_use_exec() -> None:
    assert "exec(" not in inspect.getsource(execution_module)


def test_execution_source_does_not_use_pickle() -> None:
    assert "pickle" not in inspect.getsource(execution_module)
