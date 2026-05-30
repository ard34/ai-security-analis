from __future__ import annotations

import inspect
import json
import os
import socket
import subprocess

import pytest

import core.logging as audit_logging
from core.logging import (
    AuditEvent,
    audit_event_to_dict,
    audit_event_to_json_line,
    create_audit_event,
    get_app_logger,
    read_audit_events,
    redact_sensitive_data,
    write_audit_event,
)


def test_create_audit_event_returns_audit_event() -> None:
    event = create_audit_event("scan_started", "Scan started")

    assert isinstance(event, AuditEvent)


def test_create_audit_event_sets_created_at() -> None:
    event = create_audit_event("scan_started", "Scan started")

    assert event.created_at


def test_create_audit_event_rejects_invalid_event_type() -> None:
    with pytest.raises(ValueError):
        create_audit_event("unknown", "Invalid")


def test_audit_event_to_dict_returns_dict() -> None:
    event = create_audit_event("scan_completed", "Scan completed")

    assert isinstance(audit_event_to_dict(event), dict)


def test_audit_event_to_json_line_returns_valid_json() -> None:
    event = create_audit_event("scan_completed", "Scan completed")

    assert isinstance(json.loads(audit_event_to_json_line(event)), dict)


def test_audit_event_to_json_line_contains_event_type_and_message() -> None:
    event = create_audit_event("cli_action", "CLI command executed")
    payload = json.loads(audit_event_to_json_line(event))

    assert payload["event_type"] == "cli_action"
    assert payload["message"] == "CLI command executed"


def test_redact_sensitive_data_redacts_password_key() -> None:
    assert redact_sensitive_data({"password": "secret"})["password"] == "[REDACTED]"


def test_redact_sensitive_data_is_case_insensitive() -> None:
    assert redact_sensitive_data({"Authorization": "Bearer abc"})["Authorization"] == "[REDACTED]"


def test_redact_sensitive_data_handles_nested_dict() -> None:
    payload = {"outer": {"token": "abc"}}

    assert redact_sensitive_data(payload)["outer"]["token"] == "[REDACTED]"


def test_redact_sensitive_data_handles_list_of_dict() -> None:
    payload = [{"api_key": "abc"}, {"safe": "value"}]

    assert redact_sensitive_data(payload)[0]["api_key"] == "[REDACTED]"


def test_redact_sensitive_data_does_not_mutate_input() -> None:
    payload = {"nested": {"password": "secret"}}

    sanitized = redact_sensitive_data(payload)

    assert payload["nested"]["password"] == "secret"
    assert sanitized["nested"]["password"] == "[REDACTED]"


def test_redact_sensitive_data_redacts_authorization_bearer_string() -> None:
    sanitized = redact_sensitive_data("Authorization: Bearer abc")

    assert sanitized == "Authorization: Bearer [REDACTED]"


def test_redact_sensitive_data_redacts_api_key_string() -> None:
    sanitized = redact_sensitive_data("https://example.com?api_key=abc")

    assert "api_key=[REDACTED]" in sanitized
    assert "abc" not in sanitized


def test_write_audit_event_creates_file(tmp_path) -> None:
    event = create_audit_event("scan_started", "Scan started")
    log_path = tmp_path / "audit.jsonl"

    write_audit_event(event, log_path)

    assert log_path.exists()


def test_write_audit_event_appends_jsonl(tmp_path) -> None:
    log_path = tmp_path / "audit.jsonl"

    write_audit_event(create_audit_event("scan_started", "Scan started"), log_path)
    write_audit_event(create_audit_event("scan_completed", "Scan completed"), log_path)

    assert len(log_path.read_text(encoding="utf-8").splitlines()) == 2


def test_read_audit_events_reads_events(tmp_path) -> None:
    log_path = tmp_path / "audit.jsonl"
    write_audit_event(create_audit_event("scan_started", "Scan started"), log_path)

    events = read_audit_events(log_path)

    assert events[0]["event_type"] == "scan_started"


def test_read_audit_events_returns_empty_for_missing_file(tmp_path) -> None:
    assert read_audit_events(tmp_path / "missing.jsonl") == []


def test_read_audit_events_respects_limit(tmp_path) -> None:
    log_path = tmp_path / "audit.jsonl"
    for index in range(3):
        write_audit_event(create_audit_event("cli_action", f"Command {index}"), log_path)

    assert len(read_audit_events(log_path, limit=2)) == 2


def test_read_audit_events_clamps_limit_to_1000(tmp_path) -> None:
    log_path = tmp_path / "audit.jsonl"
    for index in range(1005):
        write_audit_event(create_audit_event("cli_action", f"Command {index}"), log_path)

    assert len(read_audit_events(log_path, limit=5000)) == 1000


def test_get_app_logger_returns_logger() -> None:
    logger = get_app_logger("test_ai_security_analyst_logger")

    assert logger.name == "test_ai_security_analyst_logger"


def test_get_app_logger_does_not_double_register_handlers() -> None:
    logger = get_app_logger("test_ai_security_analyst_single_handler")
    handler_count = len(logger.handlers)

    get_app_logger("test_ai_security_analyst_single_handler")

    assert len(logger.handlers) == handler_count


def test_logging_does_not_use_network(monkeypatch, tmp_path) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in logging layer")

    monkeypatch.setattr(socket, "socket", fail_socket)

    event = create_audit_event("cli_action", "CLI command executed")
    log_path = tmp_path / "audit.jsonl"
    write_audit_event(event, log_path)

    assert log_path.exists()


def test_logging_does_not_use_subprocess(monkeypatch, tmp_path) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in logging layer")

    monkeypatch.setattr(subprocess, "run", fail_run)

    event = create_audit_event("scan_started", "Scan started")
    log_path = tmp_path / "audit.jsonl"
    write_audit_event(event, log_path)

    assert log_path.exists()


def test_logging_does_not_use_os_system(monkeypatch, tmp_path) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in logging layer")

    monkeypatch.setattr(os, "system", fail_system)

    event = create_audit_event("scan_completed", "Scan completed")
    log_path = tmp_path / "audit.jsonl"
    write_audit_event(event, log_path)

    assert log_path.exists()


def test_logging_helper_does_not_reference_forbidden_execution_apis() -> None:
    source = inspect.getsource(audit_logging)

    assert "subprocess" not in source
    assert "os.system" not in source
    assert "pickle" not in source
    assert "eval(" not in source
    assert "exec(" not in source


def test_audit_event_metadata_is_redacted() -> None:
    event = create_audit_event(
        "cli_action",
        "CLI command executed",
        metadata={"password": "secret", "nested": {"token": "abc"}},
    )
    payload = audit_event_to_dict(event)

    assert payload["metadata"]["password"] == "[REDACTED]"
    assert payload["metadata"]["nested"]["token"] == "[REDACTED]"
    assert "secret" not in json.dumps(payload)
    assert "abc" not in json.dumps(payload)


def test_read_audit_events_ignores_invalid_json_lines(tmp_path) -> None:
    log_path = tmp_path / "audit.jsonl"
    log_path.write_text("{bad json\n", encoding="utf-8")
    write_audit_event(create_audit_event("scan_completed", "Scan completed"), log_path)

    events = read_audit_events(log_path)

    assert len(events) == 1
    assert events[0]["event_type"] == "scan_completed"
