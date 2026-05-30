from __future__ import annotations

import inspect
import os
import socket
import subprocess

from ui import chat
from ui.chat import (
    append_chat_message,
    build_agent_context_from_session,
    format_agent_response_for_chat,
    handle_chat_turn,
    initialize_chat_history,
    sanitize_chat_message,
)


def test_sanitize_chat_message_trims_whitespace() -> None:
    assert sanitize_chat_message("  hello  ") == "hello"


def test_sanitize_chat_message_redacts_password() -> None:
    assert sanitize_chat_message("password=secret") == "password=[REDACTED]"


def test_sanitize_chat_message_redacts_token() -> None:
    assert sanitize_chat_message("token=abc") == "token=[REDACTED]"


def test_sanitize_chat_message_redacts_api_key() -> None:
    assert sanitize_chat_message("api_key=abc") == "api_key=[REDACTED]"


def test_sanitize_chat_message_redacts_authorization_bearer() -> None:
    assert sanitize_chat_message("Authorization: Bearer abc") == "Authorization: Bearer [REDACTED]"


def test_sanitize_chat_message_redacts_cookie_header() -> None:
    assert sanitize_chat_message("Cookie: session=abc") == "Cookie: [REDACTED]"


def test_append_chat_message_adds_user_message() -> None:
    history = append_chat_message([], "user", "hello")

    assert history == [{"role": "user", "content": "hello"}]


def test_append_chat_message_adds_assistant_message() -> None:
    history = append_chat_message([], "assistant", "hi")

    assert history == [{"role": "assistant", "content": "hi"}]


def test_append_chat_message_rejects_invalid_role() -> None:
    try:
        append_chat_message([], "admin", "hello")
    except ValueError:
        return
    raise AssertionError("invalid role should fail")


def test_append_chat_message_does_not_mutate_input() -> None:
    original = [{"role": "user", "content": "hello"}]

    updated = append_chat_message(original, "assistant", "hi")

    assert original == [{"role": "user", "content": "hello"}]
    assert len(updated) == 2


def test_initialize_chat_history_creates_default_greeting() -> None:
    history = initialize_chat_history()

    assert history[0]["role"] == "assistant"
    assert "authorized assessment" in history[0]["content"]


def test_initialize_chat_history_sanitizes_existing_history() -> None:
    history = initialize_chat_history([{"role": "user", "content": "token=abc"}])

    assert history[0]["content"] == "token=[REDACTED]"


def test_build_agent_context_from_session_takes_last_scan_result() -> None:
    context = build_agent_context_from_session({"last_scan_result": {"scan_id": "scan-001"}})

    assert context["scan_result"]["scan_id"] == "scan-001"


def test_build_agent_context_from_session_does_not_take_secret() -> None:
    context = build_agent_context_from_session({"api_token": "abc", "last_scan_result": {"token": "abc"}})

    assert "api_token" not in context
    assert context["scan_result"]["token"] == "[REDACTED]"


def test_format_agent_response_for_chat_handles_success_response() -> None:
    message = format_agent_response_for_chat({"success": True, "intent": "unknown", "message": "OK", "data": {}})

    assert "OK" in message


def test_format_agent_response_for_chat_handles_refusal_response() -> None:
    message = format_agent_response_for_chat(
        {"success": False, "intent": "unsafe_request", "message": "No", "refusal_reason": "unsafe"}
    )

    assert "Refusal reason" in message


def test_handle_chat_turn_adds_user_and_assistant_message() -> None:
    history, response = handle_chat_turn("apa kemampuan kamu?", [], project=None, context={})

    assert len(history) == 2
    assert history[0]["role"] == "user"
    assert history[1]["role"] == "assistant"
    assert response["message"]


def test_handle_chat_turn_rejects_unsafe_request() -> None:
    history, response = handle_chat_turn("exploit target", [], project=None, context={})

    assert response["success"] is False
    assert response["intent"] == "unsafe_request"
    assert history[-1]["role"] == "assistant"


def test_handle_chat_turn_does_not_call_external_llm(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("External LLM calls are not allowed")

    monkeypatch.setattr(socket, "socket", fail_socket)

    history, response = handle_chat_turn("buat rekomendasi manual testing", [], project=None, context={})

    assert history
    assert response["message"]


def test_chat_helpers_do_not_use_network(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in Chat UI helpers")

    monkeypatch.setattr(socket, "socket", fail_socket)

    history, response = handle_chat_turn("apa kemampuan kamu?", chat_history=[], project=None, context={})

    assert history
    assert response["message"]


def test_chat_helpers_do_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in Chat UI helpers")

    monkeypatch.setattr(subprocess, "run", fail_run)

    history, response = handle_chat_turn("show capabilities", chat_history=[], project=None, context={})

    assert history
    assert response["message"]


def test_chat_helpers_do_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in Chat UI helpers")

    monkeypatch.setattr(os, "system", fail_system)

    history, response = handle_chat_turn("buat rekomendasi manual testing", chat_history=[], project=None, context={})

    assert history
    assert response["message"]


def test_chat_helper_does_not_use_os_system_source() -> None:
    assert "os.system" not in inspect.getsource(chat)


def test_chat_helper_does_not_use_eval_source() -> None:
    assert "eval(" not in inspect.getsource(chat)


def test_chat_helper_does_not_use_exec_source() -> None:
    assert "exec(" not in inspect.getsource(chat)


def test_chat_helper_does_not_use_pickle_source() -> None:
    assert "pickle" not in inspect.getsource(chat)
