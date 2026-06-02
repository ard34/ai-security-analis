from __future__ import annotations

from core.workspace import create_workspace
from storage.database import connect
from storage.workspace_repository import WorkspaceRepository


def repo(tmp_path):
    return WorkspaceRepository(connect(tmp_path / "workspace.sqlite3"))


def test_save_get_list_delete_workspace(tmp_path):
    repository = repo(tmp_path)
    workspace = create_workspace()
    repository.save_workspace(workspace)

    assert repository.get_workspace(workspace.workspace_id).workspace_id == workspace.workspace_id
    assert repository.list_workspaces()

    repository.delete_workspace(workspace.workspace_id)
    assert repository.get_workspace(workspace.workspace_id) is None


def test_update_active_scan_and_chat_history(tmp_path):
    repository = repo(tmp_path)
    workspace = create_workspace()
    repository.save_workspace(workspace)

    updated = repository.update_workspace_scan(workspace.workspace_id, "scan_1")
    assert updated.active_scan_id == "scan_1"

    updated = repository.update_workspace_chat_history(
        workspace.workspace_id,
        [{"role": "user", "content": "token=secret-value"}],
    )
    assert "secret-value" not in str(updated.chat_history)


def test_append_validation_activity_and_json_safe(tmp_path):
    repository = repo(tmp_path)
    workspace = create_workspace()
    repository.save_workspace(workspace)

    updated = repository.append_validation_activity(
        workspace.workspace_id,
        finding_id="finding_1",
        old_status="validation_ready",
        new_status="accepted_risk",
        reviewer="operator",
        note="password=pw123",
        evidence_note="Authorization: Bearer abc",
    )

    assert updated.validation_activity
    assert "pw123" not in str(updated.to_dict())
    assert "abc" not in str(updated.to_dict())
