from __future__ import annotations

import json
import sqlite3

from core.workspace import (
    Workspace,
    append_workspace_chat_message,
    create_validation_activity,
    sanitize_chat_history,
    workspace_from_dict,
    workspace_now,
    workspace_to_dict,
)
from storage.database import initialize


class WorkspaceRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        initialize(connection)

    def save_workspace(self, workspace: Workspace) -> None:
        workspace.updated_at = workspace_now()
        payload = workspace_to_dict(workspace)
        self.connection.execute(
            "INSERT OR REPLACE INTO workspaces (id, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?)",
            (
                workspace.workspace_id,
                workspace.created_at,
                workspace.updated_at,
                json.dumps(payload, sort_keys=True),
            ),
        )
        self.connection.commit()

    def get_workspace(self, workspace_id: str) -> Workspace | None:
        row = self.connection.execute("SELECT payload_json FROM workspaces WHERE id = ?", (workspace_id,)).fetchone()
        if not row:
            return None
        return workspace_from_dict(json.loads(row["payload_json"]))

    def list_workspaces(self) -> list[dict[str, str]]:
        rows = self.connection.execute(
            "SELECT id, created_at, updated_at FROM workspaces ORDER BY updated_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def delete_workspace(self, workspace_id: str) -> None:
        self.connection.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))
        self.connection.commit()

    def update_workspace_scan(self, workspace_id: str, scan_id: str | None) -> Workspace:
        workspace = self._require(workspace_id)
        workspace.active_scan_id = scan_id
        self.save_workspace(workspace)
        return workspace

    def update_workspace_chat_history(self, workspace_id: str, chat_history: list[dict[str, str]]) -> Workspace:
        workspace = self._require(workspace_id)
        workspace.chat_history = sanitize_chat_history(chat_history)
        self.save_workspace(workspace)
        return workspace

    def append_chat_message(self, workspace_id: str, *, role: str, content: str) -> Workspace:
        workspace = self._require(workspace_id)
        append_workspace_chat_message(workspace, role=role, content=content)
        self.save_workspace(workspace)
        return workspace

    def append_validation_activity(
        self,
        workspace_id: str,
        *,
        finding_id: str,
        old_status: str,
        new_status: str,
        reviewer: str = "",
        note: str = "",
        evidence_note: str = "",
    ) -> Workspace:
        workspace = self._require(workspace_id)
        workspace.validation_activity.append(
            create_validation_activity(
                finding_id=finding_id,
                old_status=old_status,
                new_status=new_status,
                reviewer=reviewer,
                note=note,
                evidence_note=evidence_note,
            )
        )
        self.save_workspace(workspace)
        return workspace

    def _require(self, workspace_id: str) -> Workspace:
        workspace = self.get_workspace(workspace_id)
        if not workspace:
            raise KeyError("workspace not found")
        return workspace
