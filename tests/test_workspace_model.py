from __future__ import annotations

import pytest

from core.workspace import (
    append_workspace_chat_message,
    create_validation_activity,
    create_workspace,
    sanitize_chat_history,
    trim_chat_history,
    workspace_from_dict,
    workspace_to_dict,
)


def test_workspace_created_with_id_and_roundtrip():
    workspace = create_workspace(assessment_id="assessment-1")
    loaded = workspace_from_dict(workspace_to_dict(workspace))

    assert workspace.workspace_id.startswith("workspace_")
    assert loaded.workspace_id == workspace.workspace_id
    assert loaded.assessment_id == "assessment-1"


def test_chat_history_redaction_and_trim():
    history = [
        {"role": "user", "content": "Authorization: Bearer abc123 token=secret password=pw"},
        *[{"role": "assistant", "content": f"m{i}"} for i in range(105)],
    ]
    sanitized = sanitize_chat_history(history)

    assert len(sanitized) == 100
    assert "abc123" not in str(sanitized)
    assert "secret" not in str(sanitized)
    assert len(trim_chat_history(history, max_messages=3)) == 3


def test_append_workspace_chat_message_limits_content():
    workspace = create_workspace()
    append_workspace_chat_message(workspace, role="user", content="x" * 3000)

    assert len(workspace.chat_history[0]["content"]) == 2000


def test_validation_activity_created_and_redacted():
    activity = create_validation_activity(
        finding_id="finding_1",
        old_status="validation_ready",
        new_status="false_positive",
        reviewer="operator",
        note="api_key=secret-value",
        evidence_note="cookie=session-value",
    )

    assert activity.timestamp
    assert "secret-value" not in str(activity.to_dict())
    assert "session-value" not in str(activity.to_dict())


def test_invalid_validation_activity_status_rejected():
    with pytest.raises(ValueError):
        create_validation_activity(finding_id="x", old_status="potential", new_status="bad")
