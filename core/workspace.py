from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from core.finding_validation import UI_VALIDATION_STATUSES, sanitize_validation_note
from core.policies import redact_value

MAX_CHAT_MESSAGES = 100
MAX_CHAT_MESSAGE_LENGTH = 2_000
CHAT_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|cookie|session)\s*[:=]\s*)[^\s,;]+"),
]


def workspace_now() -> str:
    return datetime.now(UTC).isoformat()


def new_workspace_id() -> str:
    return f"workspace_{uuid4().hex[:12]}"


@dataclass(slots=True)
class ValidationActivity:
    finding_id: str
    old_status: str
    new_status: str
    reviewer: str = ""
    note: str = ""
    evidence_note: str = ""
    timestamp: str = field(default_factory=workspace_now)

    def to_dict(self) -> dict[str, str]:
        return validation_activity_to_dict(self)


@dataclass(slots=True)
class Workspace:
    workspace_id: str = field(default_factory=new_workspace_id)
    assessment_id: str | None = None
    active_scan_id: str | None = None
    active_finding_id: str | None = None
    chat_history: list[dict[str, str]] = field(default_factory=list)
    validation_activity: list[ValidationActivity] = field(default_factory=list)
    created_at: str = field(default_factory=workspace_now)
    updated_at: str = field(default_factory=workspace_now)

    def to_dict(self) -> dict[str, object]:
        return workspace_to_dict(self)


def create_workspace(*, assessment_id: str | None = None) -> Workspace:
    return Workspace(assessment_id=assessment_id)


def workspace_to_dict(workspace: Workspace) -> dict[str, object]:
    data = asdict(workspace)
    data["chat_history"] = sanitize_chat_history(workspace.chat_history)
    data["validation_activity"] = [activity.to_dict() for activity in workspace.validation_activity]
    return data


def workspace_from_dict(data: dict[str, Any]) -> Workspace:
    activities = [create_validation_activity(**item) for item in data.get("validation_activity", [])]
    return Workspace(
        workspace_id=str(data.get("workspace_id") or new_workspace_id()),
        assessment_id=data.get("assessment_id"),  # type: ignore[arg-type]
        active_scan_id=data.get("active_scan_id"),  # type: ignore[arg-type]
        active_finding_id=data.get("active_finding_id"),  # type: ignore[arg-type]
        chat_history=sanitize_chat_history(list(data.get("chat_history", []))),
        validation_activity=activities,
        created_at=str(data.get("created_at") or workspace_now()),
        updated_at=str(data.get("updated_at") or workspace_now()),
    )


def sanitize_chat_history(history: list[dict[str, str]]) -> list[dict[str, str]]:
    sanitized: list[dict[str, str]] = []
    for message in history:
        role = str(message.get("role", "assistant"))
        content = _sanitize_chat_content(str(message.get("content", "")))
        if content:
            sanitized.append({"role": role[:32], "content": content})
    return trim_chat_history(sanitized)


def append_workspace_chat_message(workspace: Workspace, *, role: str, content: str) -> Workspace:
    content = _sanitize_chat_content(content)
    if not content:
        return workspace
    workspace.chat_history.append({"role": role[:32], "content": content})
    workspace.chat_history = trim_chat_history(workspace.chat_history)
    workspace.updated_at = workspace_now()
    return workspace


def trim_chat_history(history: list[dict[str, str]], *, max_messages: int = MAX_CHAT_MESSAGES) -> list[dict[str, str]]:
    return history[-max_messages:]


def create_validation_activity(
    *,
    finding_id: str,
    old_status: str,
    new_status: str,
    reviewer: str = "",
    note: str = "",
    evidence_note: str = "",
    timestamp: str | None = None,
) -> ValidationActivity:
    if new_status not in UI_VALIDATION_STATUSES:
        raise ValueError("invalid validation status")
    return ValidationActivity(
        finding_id=finding_id,
        old_status=old_status,
        new_status=new_status,
        reviewer=sanitize_validation_note(reviewer),
        note=sanitize_validation_note(note),
        evidence_note=sanitize_validation_note(evidence_note),
        timestamp=timestamp or workspace_now(),
    )


def validation_activity_to_dict(activity: ValidationActivity) -> dict[str, str]:
    return {
        "finding_id": activity.finding_id,
        "old_status": activity.old_status,
        "new_status": activity.new_status,
        "reviewer": sanitize_validation_note(activity.reviewer),
        "note": sanitize_validation_note(activity.note),
        "evidence_note": sanitize_validation_note(activity.evidence_note),
        "timestamp": activity.timestamp,
    }


def restore_workspace_state(workspace: Workspace) -> dict[str, object]:
    return {
        "workspace_id": workspace.workspace_id,
        "assessment_id": workspace.assessment_id,
        "active_scan_id": workspace.active_scan_id,
        "active_finding_id": workspace.active_finding_id,
        "chat_history": sanitize_chat_history(workspace.chat_history),
        "validation_activity": [activity.to_dict() for activity in workspace.validation_activity],
    }


def _sanitize_chat_content(content: str) -> str:
    sanitized = str(redact_value("chat", content.strip()))
    for pattern in CHAT_SECRET_PATTERNS:
        sanitized = pattern.sub(r"\1[REDACTED]", sanitized)
    if len(sanitized) > MAX_CHAT_MESSAGE_LENGTH:
        sanitized = sanitized[:MAX_CHAT_MESSAGE_LENGTH]
    return sanitized
