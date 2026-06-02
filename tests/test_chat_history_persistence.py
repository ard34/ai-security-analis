from __future__ import annotations

from core.workspace import append_workspace_chat_message, create_workspace, sanitize_chat_history


def test_append_user_and_assistant_messages():
    workspace = create_workspace()
    append_workspace_chat_message(workspace, role="user", content="hello")
    append_workspace_chat_message(workspace, role="assistant", content="answer")

    assert [message["role"] for message in workspace.chat_history] == ["user", "assistant"]


def test_chat_history_redacts_sensitive_text():
    history = sanitize_chat_history(
        [
            {"role": "user", "content": "Authorization: Bearer abc123"},
            {"role": "user", "content": "cookie=session token=tok password=pw api_key=key"},
        ]
    )
    text = str(history)

    for secret in ["abc123", "session ", "tok ", "pw ", "key'"]:
        assert secret not in text
    assert "token=[REDACTED]" in text


def test_chat_history_enforces_max_length_and_rejects_empty_oversized_data():
    workspace = create_workspace()
    append_workspace_chat_message(workspace, role="user", content=" ")
    assert workspace.chat_history == []

    append_workspace_chat_message(workspace, role="user", content="x" * 5000)
    assert len(workspace.chat_history[0]["content"]) == 2000
