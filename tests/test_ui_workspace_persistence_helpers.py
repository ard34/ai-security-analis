from __future__ import annotations

from core.pipeline_source import run_source_assessment
from core.workspace import create_workspace
from storage.database import connect
from storage.repositories import ScanRepository
from storage.workspace_repository import WorkspaceRepository
from ui.app import (
    build_workspace_sidebar_rows,
    can_export_from_ui,
    can_restore_selected_finding,
    initialize_workspace_state,
    load_saved_scans_for_sidebar,
    persist_chat_turn,
    persist_validation_update,
    select_finding_for_workspace,
    select_scan_for_workspace,
)


def test_initialize_workspace_state(tmp_path):
    repository = WorkspaceRepository(connect(tmp_path / "db.sqlite3"))
    session_state = {}

    workspace = initialize_workspace_state(session_state, workspace_repository=repository)

    assert workspace.workspace_id
    assert session_state["workspace_id"] == workspace.workspace_id
    assert session_state["chat_messages"] == []


def test_load_and_select_saved_scan(tmp_path):
    connection = connect(tmp_path / "db.sqlite3")
    scan_repository = ScanRepository(connection)
    result = run_source_assessment("tests/fixtures/source_logic_cases", logic_analysis=True)
    scan_repository.save(result)
    workspace = create_workspace()
    session_state = {}

    rows = load_saved_scans_for_sidebar(scan_repository)
    selected = select_scan_for_workspace(session_state, scan_repository, workspace, result.id)

    assert rows[0]["id"] == result.id
    assert selected.id == result.id
    assert can_export_from_ui(selected) is True


def test_select_and_restore_finding():
    result = run_source_assessment("tests/fixtures/source_logic_cases", logic_analysis=True)
    workspace = create_workspace()
    session_state = {}
    finding = result.findings[0]

    selected = select_finding_for_workspace(session_state, workspace, result, finding.id)

    assert selected.id == finding.id
    assert can_restore_selected_finding(result, finding.id) is True
    assert can_restore_selected_finding(result, "missing") is False


def test_persist_chat_and_validation_update_redacts():
    workspace = create_workspace()
    persist_chat_turn(workspace, user_message="token=secret", assistant_message="ok")
    persist_validation_update(
        workspace,
        finding_id="finding_1",
        old_status="validation_ready",
        new_status="false_positive",
        reviewer="operator",
        note="api_key=secret",
        evidence_note="cookie=session",
    )

    assert "secret" not in str(workspace.to_dict())
    assert "session" not in str(workspace.to_dict())


def test_build_workspace_sidebar_rows():
    rows = build_workspace_sidebar_rows([{"id": "workspace_1"}], [{"id": "scan_1"}])

    assert rows["workspaces"]
    assert rows["scans"]
