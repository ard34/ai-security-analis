from __future__ import annotations

import html
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.assessment import Assessment
from core.finding_dedup import deduplicate_findings
from core.finding_validation import (
    build_validation_status_options,
    update_finding_validation_status,
)
from core.finding_validation import (
    can_mark_finding_manually_confirmed as core_can_mark_finding_manually_confirmed,
)
from core.finding_validation import (
    sanitize_validation_note as core_sanitize_validation_note,
)
from core.logging import read_audit_log
from core.models import Finding, ScanResult
from core.pipeline_domain import run_domain_assessment
from core.pipeline_source import run_source_assessment
from core.policies import DomainRunPolicy, redact_value
from core.scope import ScopeError
from core.workspace import Workspace, append_workspace_chat_message, create_workspace, restore_workspace_state
from reporting.html_report import render_html_report
from reporting.pdf_report import render_pdf_report
from storage.database import connect
from storage.repositories import ScanRepository
from storage.workspace_repository import WorkspaceRepository
from ui.chat import handle_copilot_chat_turn, summarize_scan_for_copilot

TYPE1_MODE = "Type 1 — Source Folder Assessment"
TYPE2_MODE = "Type 2 — Domain Safe-Live Assessment"
DB_PATH = Path("data/ai_security_analyst.sqlite3")


def _scan_repo() -> ScanRepository:
    return ScanRepository(connect(DB_PATH))


def mode_options() -> list[str]:
    return [TYPE1_MODE, TYPE2_MODE]


def build_sidebar_navigation_state(selected: str = "Source Code Analysis") -> dict[str, object]:
    items = [
        "New Assessment",
        "Assessment Projects",
        "Source Code Analysis",
        "Domain Safe-Live",
        "Scan History",
        "Reports",
        "Settings/Safety",
    ]
    active = selected if selected in items else "Source Code Analysis"
    return {"items": items, "active": active}


def build_source_analysis_form_state(source_path: str, *, logic_analysis: bool = False) -> dict[str, object]:
    path = source_path.strip()
    return {
        "source_path": path,
        "logic_analysis": bool(logic_analysis),
        "local_only": True,
        "can_run": can_run_source_logic_analysis_from_ui(path),
    }


def can_run_source_logic_analysis_from_ui(source_path: str) -> bool:
    return bool(source_path.strip() and Path(source_path).expanduser().exists())


def run_source_logic_analysis_from_ui(source_path: str, *, logic_analysis: bool = True) -> ScanResult:
    if not can_run_source_logic_analysis_from_ui(source_path):
        raise ValueError("source path is required and must exist")
    return run_source_assessment(source_path, logic_analysis=logic_analysis)


def findings_to_workspace_rows(result: ScanResult | None) -> list[dict[str, object]]:
    if not result:
        return []
    return [
        {
            "index": index,
            "title": finding.title,
            "severity": finding.severity,
            "validation_status": finding.validation_status,
            "confidence_score": finding.confidence_score,
            "source_locations": finding.source_locations,
        }
        for index, finding in enumerate(result.findings)
    ]


def get_selected_finding(result: ScanResult | None, selected_index: int | None = None) -> Finding | None:
    if not result or not result.findings:
        return None
    index = selected_index if selected_index is not None else 0
    if index < 0 or index >= len(result.findings):
        return None
    return result.findings[index]


def can_mark_finding_manually_confirmed(*, reviewer: str, note: str, evidence_note: str) -> bool:
    return core_can_mark_finding_manually_confirmed(reviewer=reviewer, note=note, evidence_note=evidence_note)


def sanitize_validation_note(note: str) -> str:
    return core_sanitize_validation_note(note)


def build_finding_detail_view_model(finding: Finding | None) -> dict[str, object]:
    if not finding:
        return {"selected": False}
    plan = finding.metadata.get("manual_validation_plan", {})
    return sanitize_dashboard_display_data(
        {
            "selected": True,
            "title": finding.title,
            "severity": finding.severity,
            "confidence_score": finding.confidence_score,
            "validation_status": finding.validation_status,
            "source_locations": finding.source_locations,
            "affected_routes": finding.affected_routes,
            "affected_functions": finding.affected_functions,
            "vulnerable_flow": finding.vulnerable_flow,
            "root_cause": finding.root_cause,
            "missing_control": finding.missing_control,
            "attacker_model": finding.attacker_model,
            "preconditions": finding.preconditions,
            "exploitability_reasoning": finding.exploitability_reasoning,
            "manual_validation_steps": finding.manual_validation_steps,
            "expected_evidence": finding.expected_evidence,
            "false_positive_checks": finding.false_positive_checks,
            "remediation_guidance": finding.remediation_guidance,
            "manual_validation_plan": plan,
        }
    )


def can_export_from_ui(last_scan_result: ScanResult | None) -> bool:
    return can_export_dashboard_result(last_scan_result)


def build_safety_status_banner(
    *,
    mode: str = "Local-only",
    assessment: Assessment | None = None,
    target: str = "",
    network_allowed: bool = False,
    confirmed: bool = False,
    kill_switch_enabled: bool = False,
) -> dict[str, object]:
    in_scope = False
    if assessment and target.strip():
        try:
            in_scope = assessment.scope().contains(target)
        except ScopeError:
            in_scope = False
    return {
        "mode": mode,
        "assessment_approved": bool(assessment and assessment.approved),
        "target_in_scope": in_scope,
        "network_allowed": network_allowed,
        "confirmation": confirmed,
        "kill_switch": "enabled" if kill_switch_enabled else "disabled",
    }


def build_no_scan_selected_message() -> str:
    return "No scan is selected. Run Source Code Analysis or load a saved scan from the sidebar."


def build_no_finding_selected_message() -> str:
    return "No finding is selected. Select a validation-ready finding to review source and validation details."


def build_export_unavailable_reason(last_scan_result: ScanResult | None) -> str:
    if can_export_from_ui(last_scan_result):
        return ""
    return "Export is unavailable until a scan result is loaded."


def build_manual_confirmation_warning() -> str:
    return "Only mark as manually_confirmed after authorized manual validation with evidence."


def build_streamlit_missing_message() -> str:
    return "Streamlit is optional. Install UI dependencies with: python -m pip install -r requirements-ui.txt"


def build_source_analysis_disabled_reason(source_path: str) -> str:
    if source_path.strip():
        if Path(source_path).expanduser().exists():
            return ""
        return "Source analysis is disabled because the local path does not exist."
    return "Source analysis is disabled until a local source path is provided."


def initialize_workspace_state(
    session_state: dict[str, Any],
    *,
    workspace_repository: WorkspaceRepository | None = None,
) -> Workspace:
    workspace = session_state.get("workspace")
    if isinstance(workspace, Workspace):
        return workspace
    rows = workspace_repository.list_workspaces() if workspace_repository else []
    loaded = workspace_repository.get_workspace(rows[0]["id"]) if workspace_repository and rows else None
    workspace = loaded or create_workspace()
    session_state["workspace"] = workspace
    restored = restore_workspace_state(workspace)
    session_state["workspace_id"] = restored["workspace_id"]
    session_state["chat_messages"] = restored["chat_history"]
    session_state["selected_finding_id"] = restored["active_finding_id"]
    return workspace


def load_saved_scans_for_sidebar(scan_repository: Any) -> list[dict[str, str]]:
    return scan_repository.list()


def select_scan_for_workspace(
    session_state: dict[str, Any],
    scan_repository: Any,
    workspace: Workspace,
    scan_id: str,
) -> ScanResult | None:
    result = scan_repository.get(scan_id)
    if not result:
        return None
    workspace.active_scan_id = result.id
    session_state["last_scan_result"] = result
    session_state["workspace"] = workspace
    return result


def select_finding_for_workspace(
    session_state: dict[str, Any],
    workspace: Workspace,
    result: ScanResult | None,
    finding_id: str,
) -> Finding | None:
    if not result:
        return None
    for index, finding in enumerate(result.findings):
        if finding.id == finding_id:
            workspace.active_finding_id = finding_id
            session_state["selected_finding_id"] = finding_id
            session_state["selected_finding_index"] = index
            session_state["workspace"] = workspace
            return finding
    return None


def can_restore_selected_finding(result: ScanResult | None, finding_id: str | None) -> bool:
    return bool(result and finding_id and any(finding.id == finding_id for finding in result.findings))


def persist_chat_turn(
    workspace: Workspace,
    *,
    user_message: str,
    assistant_message: str,
    workspace_repository: WorkspaceRepository | None = None,
) -> Workspace:
    append_workspace_chat_message(workspace, role="user", content=user_message)
    append_workspace_chat_message(workspace, role="assistant", content=assistant_message)
    if workspace_repository:
        workspace_repository.save_workspace(workspace)
    return workspace


def persist_validation_update(
    workspace: Workspace,
    *,
    finding_id: str,
    old_status: str,
    new_status: str,
    reviewer: str = "",
    note: str = "",
    evidence_note: str = "",
    workspace_repository: WorkspaceRepository | None = None,
) -> Workspace:
    if workspace_repository:
        return workspace_repository.append_validation_activity(
            workspace.workspace_id,
            finding_id=finding_id,
            old_status=old_status,
            new_status=new_status,
            reviewer=reviewer,
            note=note,
            evidence_note=evidence_note,
        )
    from core.workspace import create_validation_activity

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
    return workspace


def build_workspace_sidebar_rows(workspaces: list[dict[str, str]], scans: list[dict[str, str]]) -> dict[str, object]:
    return {"workspaces": workspaces, "scans": scans}


def sanitize_workspace_display_data(data: Any) -> Any:
    return sanitize_dashboard_display_data(data)


def can_enable_domain_mode(assessment: Assessment | None, confirmed: bool) -> bool:
    return bool(assessment and assessment.approved and confirmed)


def load_dashboard_assessment_json(raw_json: str) -> tuple[Assessment | None, str | None, str | None]:
    if not raw_json.strip():
        return None, None, "assessment JSON is required"
    try:
        data = json.loads(raw_json)
        if not isinstance(data, dict):
            return None, None, "assessment JSON must be an object"
        assessment = Assessment.from_dict(data)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return None, None, f"invalid assessment JSON: {exc}"
    note = (
        assessment.authorization_note
        or data.get("authorization_note")
        or data.get("authorization")
        or data.get("note")
    )
    return assessment, str(note) if note else None, None


def _split_scope_values(value: str | list[str]) -> list[str]:
    if isinstance(value, list):
        items = value
    else:
        items = value.replace("\n", ",").split(",")
    return [str(item).strip().lower().rstrip(".") for item in items if str(item).strip()]


def build_assessment_form_state(
    *,
    name: str,
    target: str,
    allowed_domains: str | list[str],
    allowed_ips: str | list[str] = "",
    owner_operator: str = "",
    authorization_note: str = "",
    environment: str = "pre-production",
) -> Assessment:
    domains = _split_scope_values(allowed_domains)
    normalized_target = target.strip().lower().rstrip(".")
    if normalized_target and normalized_target not in domains:
        domains.append(normalized_target)
    return Assessment(
        name=name.strip(),
        allowed_targets=domains,
        owner_operator=owner_operator.strip(),
        authorization_note=str(redact_value("authorization_note", authorization_note.strip())),
        environment=environment.strip() or "pre-production",
        allowed_ips=_split_scope_values(allowed_ips),
    )


def assessment_scope_to_display_rows(assessment: Assessment | None) -> list[dict[str, str]]:
    if not assessment:
        return []
    rows = [{"type": "domain", "value": item} for item in assessment.allowed_targets]
    rows.extend({"type": "ip", "value": item} for item in assessment.allowed_ips)
    return sanitize_dashboard_display_data(rows)


def can_approve_assessment_from_ui(assessment: Assessment | None) -> bool:
    if not assessment:
        return False
    if assessment.status == "archived":
        return False
    if not assessment.name.strip() or not assessment.allowed_targets:
        return False
    if not assessment.owner_operator.strip() or not assessment.authorization_note.strip():
        return False
    try:
        assessment.scope()
    except ScopeError:
        return False
    return True


def can_archive_assessment_from_ui(assessment: Assessment | None) -> bool:
    return bool(assessment and assessment.status != "archived")


def summarize_assessment_project(assessment: Assessment | None) -> dict[str, Any]:
    if not assessment:
        return {"status": "missing", "allowed_scope": []}
    return sanitize_assessment_display_data(
        {
            "name": assessment.name,
            "status": assessment.status,
            "approved": assessment.approved,
            "owner_operator": assessment.owner_operator,
            "environment": assessment.environment,
            "authorization_note": html.escape(str(assessment.authorization_note), quote=True),
            "allowed_scope": assessment_scope_to_display_rows(assessment),
            "created_at": assessment.created_at,
            "approved_at": assessment.approved_at,
            "archived_at": assessment.archived_at,
        }
    )


def filter_scan_history_by_assessment(
    history: list[dict[str, Any]], assessment: Assessment | None
) -> list[dict[str, Any]]:
    if not assessment:
        return []
    filtered: list[dict[str, Any]] = []
    for row in history:
        target = str(row.get("target", ""))
        assessment_name = str(row.get("assessment_name") or row.get("assessment") or "")
        if assessment_name == assessment.name:
            filtered.append(row)
            continue
        try:
            if target and assessment.scope().contains(target):
                filtered.append(row)
        except ScopeError:
            continue
    return sanitize_dashboard_display_data(filtered)


def sanitize_assessment_display_data(data: Any) -> Any:
    return sanitize_dashboard_display_data(data)


def summarize_assessment_status(
    assessment: Assessment | None,
    target: str = "",
    *,
    authorization_note: str | None = None,
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "approved": bool(assessment and assessment.approved),
        "status": assessment.status if assessment else "missing",
        "allowed_scope": list(assessment.allowed_targets) if assessment else [],
        "target_in_scope": False,
        "authorization_note": html.escape(
            str(redact_value("authorization_note", authorization_note or "")), quote=True
        ),
    }
    if not assessment:
        status["reason"] = "assessment JSON is not loaded"
        return status
    if target.strip():
        try:
            status["target_in_scope"] = assessment.scope().contains(target)
        except ScopeError as exc:
            status["target_in_scope"] = False
            status["reason"] = str(exc)
    else:
        status["reason"] = "target domain is required"
    return status


def safe_live_gate_reasons(
    *,
    assessment: Assessment | None,
    target: str,
    confirmed: bool,
    safe_live: bool,
    allow_network: bool,
    audit_log_path: str | None,
) -> list[str]:
    reasons: list[str] = []
    if not assessment:
        reasons.append("assessment JSON is not loaded")
        return reasons
    if assessment.status == "archived":
        reasons.append("assessment is archived")
    if not assessment.approved:
        reasons.append("assessment is not approved")
    if not target.strip():
        reasons.append("target domain is required")
    else:
        try:
            if not assessment.scope().contains(target):
                reasons.append("target is out of scope")
        except ScopeError as exc:
            reasons.append(str(exc))
    if not confirmed:
        reasons.append("authorization and scope confirmation is required")
    if not safe_live:
        reasons.append("safe-live passive recon must be enabled")
    if not allow_network:
        reasons.append("limited network actions must be explicitly allowed")
    if not audit_log_path or not audit_log_path.strip():
        reasons.append("audit log path is required")
    return reasons


def can_run_safe_live_from_dashboard(
    *,
    assessment: Assessment | None,
    target: str,
    confirmed: bool,
    safe_live: bool,
    allow_network: bool,
    audit_log_path: str | None,
) -> bool:
    return not safe_live_gate_reasons(
        assessment=assessment,
        target=target,
        confirmed=confirmed,
        safe_live=safe_live,
        allow_network=allow_network,
        audit_log_path=audit_log_path,
    )


def can_run_domain_scan_for_assessment(
    *,
    assessment: Assessment | None,
    target: str,
    confirmed: bool,
    safe_live: bool,
    allow_network: bool,
    audit_log_path: str | None,
) -> bool:
    return can_run_safe_live_from_dashboard(
        assessment=assessment,
        target=target,
        confirmed=confirmed,
        safe_live=safe_live,
        allow_network=allow_network,
        audit_log_path=audit_log_path,
    )


def build_dashboard_live_config(
    *,
    safe_live: bool,
    allow_network: bool,
    confirmed: bool,
    audit_log_path: str,
    timeout_seconds: float = 5.0,
    rate_limit_per_second: float = 1.0,
    scan_budget: int = 8,
) -> DomainRunPolicy:
    return DomainRunPolicy(
        safe_live=safe_live,
        allow_network=allow_network,
        confirm_safe_live=confirmed,
        timeout_seconds=timeout_seconds,
        rate_limit_per_second=rate_limit_per_second,
        scan_budget=scan_budget,
        audit_log_path=audit_log_path,
    )


def sanitize_dashboard_display_data(data: Any) -> Any:
    if isinstance(data, ScanResult):
        return sanitize_dashboard_display_data(data.to_dict())
    if isinstance(data, dict):
        return {key: sanitize_dashboard_display_data(redact_value(str(key), value)) for key, value in data.items()}
    if isinstance(data, list):
        return [sanitize_dashboard_display_data(item) for item in data]
    return redact_value("value", data)


def can_export_dashboard_result(last_scan_result: ScanResult | None) -> bool:
    return last_scan_result is not None


def dashboard_result_exports(result: ScanResult | None) -> dict[str, bytes | str]:
    if not can_export_dashboard_result(result):
        return {}
    assert result is not None
    safe_result = ScanResult.from_dict(sanitize_dashboard_display_data(result.to_dict()))
    return {
        "json": json.dumps(safe_result.to_dict(), indent=2, sort_keys=True),
        "html": render_html_report(safe_result),
        "pdf": render_pdf_report(safe_result),
    }


def run_safe_live_from_dashboard(
    *,
    target: str,
    assessment: Assessment,
    policy: DomainRunPolicy,
) -> ScanResult:
    return run_domain_assessment(target, assessment, policy)


def _render_scan_result(st: Any, result: ScanResult) -> None:
    safe_data = sanitize_dashboard_display_data(result)
    findings = result.findings
    deduped = deduplicate_findings(list(result.findings))
    st.subheader("Scan result")
    st.json(
        {
            "status": "completed",
            "target": result.target,
            "workflow": result.workflow,
            "execution_context": safe_data.get("metadata", {}) if isinstance(safe_data, dict) else {},
        }
    )
    sections = {
        "Assets": safe_data.get("assets", []),
        "Endpoints": safe_data.get("endpoints", []),
        "Findings": sanitize_dashboard_display_data([item.to_dict() for item in findings]),
        "Deduped findings": sanitize_dashboard_display_data([item.to_dict() for item in deduped]),
        "Evidence": safe_data.get("evidence", []),
        "Manual testing recommendations": safe_data.get("recommendations", []),
        "Audit log": safe_data.get("audit_events", []),
    }
    for title, payload in sections.items():
        st.subheader(title)
        st.json(sanitize_dashboard_display_data(payload))


def _render_export_buttons(st: Any, result: ScanResult | None) -> None:
    exports = dashboard_result_exports(result)
    disabled = not exports
    if disabled:
        st.info(build_export_unavailable_reason(result))
    st.download_button("Export JSON", data=exports.get("json", ""), file_name="scan-result.json", disabled=disabled)
    st.download_button("Export HTML", data=exports.get("html", ""), file_name="scan-result.html", disabled=disabled)
    st.download_button(
        "Export PDF",
        data=exports.get("pdf", b""),
        file_name="scan-result.pdf",
        mime="application/pdf",
        disabled=disabled,
    )


def _render_type1(st: Any) -> None:
    source_path = st.text_input("Local folder path")
    logic_analysis = st.checkbox("Enable logic analysis", value=True)
    disabled_reason = build_source_analysis_disabled_reason(source_path)
    if disabled_reason:
        st.info(disabled_reason)
    if st.button("Run Source Analysis", disabled=bool(disabled_reason)) and source_path:
        st.session_state["last_scan_result"] = run_source_logic_analysis_from_ui(
            source_path, logic_analysis=logic_analysis
        )
    result = st.session_state.get("last_scan_result")
    if result:
        _render_scan_result(st, result)
    _render_export_buttons(st, result)


def _render_finding_workspace(st: Any, result: ScanResult | None) -> None:
    rows = findings_to_workspace_rows(result)
    st.subheader("Findings")
    if not rows:
        st.info(build_no_finding_selected_message())
        return
    labels = [f"{row['index']}: {row['severity']} - {row['title']}" for row in rows]
    selected_label = st.selectbox("Selected finding", labels)
    selected_index = int(str(selected_label).split(":", 1)[0])
    finding = get_selected_finding(result, selected_index)
    st.session_state["selected_finding_index"] = selected_index
    st.json(build_finding_detail_view_model(finding))
    st.warning(build_manual_confirmation_warning())
    if finding:
        status = st.selectbox("Validation status", build_validation_status_options(), index=0)
        reviewer = st.text_input("Reviewer/operator")
        note = st.text_area("Validation note")
        evidence_note = st.text_area("Evidence note")
        if st.button("Update validation status"):
            try:
                old_status = finding.validation_status
                update_finding_validation_status(
                    finding,
                    status=status,
                    reviewer=reviewer,
                    note=note,
                    evidence_note=evidence_note,
                    actor="manual",
                )
                workspace = st.session_state.get("workspace")
                if isinstance(workspace, Workspace):
                    persist_validation_update(
                        workspace,
                        finding_id=finding.id,
                        old_status=old_status,
                        new_status=status,
                        reviewer=reviewer,
                        note=note,
                        evidence_note=evidence_note,
                    )
                st.success("Validation status updated in current session.")
            except ValueError as exc:
                st.error(str(exc))


def _render_copilot_chat(st: Any, result: ScanResult | None) -> None:
    st.subheader("Copilot")
    messages = st.session_state.setdefault("chat_messages", [])
    for message in messages:
        with st.chat_message(message["role"]):
            st.write(message["content"])
    selected = get_selected_finding(result, st.session_state.get("selected_finding_index"))
    prompt = st.chat_input("Ask about the current scan, finding, validation plan, or report export")
    if prompt:
        messages.append({"role": "user", "content": prompt})
        answer = handle_copilot_chat_turn(prompt, scan_result=result, selected_finding=selected)
        messages.append({"role": "assistant", "content": answer})
        workspace = st.session_state.get("workspace")
        if isinstance(workspace, Workspace):
            persist_chat_turn(workspace, user_message=prompt, assistant_message=answer)
        st.rerun()


def _render_copilot_workspace(st: Any) -> None:
    st.set_page_config(page_title="AI Security Analyst Copilot", layout="wide")
    workspace = initialize_workspace_state(st.session_state)
    navigation = build_sidebar_navigation_state(st.session_state.get("nav_active", "Source Code Analysis"))
    with st.sidebar:
        st.title("AI Security Analyst")
        nav = st.radio("Workspace", navigation["items"], index=navigation["items"].index(navigation["active"]))
        st.session_state["nav_active"] = nav
        st.caption("Local-first copilot workspace")
        st.caption(f"Workspace: {workspace.workspace_id}")
        try:
            scan_repository = _scan_repo()
            scan_rows = load_saved_scans_for_sidebar(scan_repository)
        except OSError:
            scan_rows = []
        if scan_rows:
            selected_scan = st.selectbox("Saved scans", [row["id"] for row in scan_rows])
            if st.button("Load selected scan"):
                select_scan_for_workspace(st.session_state, scan_repository, workspace, selected_scan)

    result = st.session_state.get("last_scan_result")
    st.title("AI Security Analyst Copilot")
    st.json(build_safety_status_banner(mode="Local-only"))

    if st.session_state.get("nav_active") == "Domain Safe-Live":
        _render_type2(st)
        return
    if st.session_state.get("nav_active") == "Source Code Analysis":
        with st.expander("Run Source Code Analysis", expanded=not result):
            _render_type1(st)

    left, right = st.columns([2, 1])
    with left:
        st.caption(summarize_scan_for_copilot(result))
        _render_copilot_chat(st, result)
        if not result:
            st.info(build_no_scan_selected_message())
        else:
            st.subheader("Scan Result")
            st.json(sanitize_dashboard_display_data(result.to_dict()))
    with right:
        _render_finding_workspace(st, result)
        _render_export_buttons(st, result)


def _render_assessment_workflow(st: Any) -> Assessment | None:
    st.subheader("Assessment Workflow")
    name = st.text_input("Assessment name")
    target = st.text_input("Assessment target")
    allowed_domains = st.text_area("Allowed domains")
    allowed_ips = st.text_area("Allowed IPs optional")
    owner_operator = st.text_input("Owner/operator")
    authorization_note = st.text_area("Authorization note")
    environment = st.text_input("Environment/pre-production label", value="pre-production")

    if st.button("Create Assessment Draft"):
        st.session_state["assessment_project"] = build_assessment_form_state(
            name=name,
            target=target,
            allowed_domains=allowed_domains,
            allowed_ips=allowed_ips,
            owner_operator=owner_operator,
            authorization_note=authorization_note,
            environment=environment,
        )

    assessment = st.session_state.get("assessment_project")
    if assessment:
        if st.button("Approve Assessment", disabled=not can_approve_assessment_from_ui(assessment)):
            assessment.approve()
            st.session_state["assessment_project"] = assessment
        if st.button("Archive Assessment", disabled=not can_archive_assessment_from_ui(assessment)):
            assessment.archive()
            st.session_state["assessment_project"] = assessment
        st.json(summarize_assessment_project(assessment))
        st.subheader("Allowed scope")
        st.json(assessment_scope_to_display_rows(assessment))
        st.subheader("Scan history")
        st.json(filter_scan_history_by_assessment(st.session_state.get("scan_history", []), assessment))
    return assessment


def _render_type2(st: Any) -> None:
    workflow_assessment = _render_assessment_workflow(st)
    target = st.text_input("Target domain")
    assessment_path = st.text_input("Assessment JSON path")
    raw_json = st.text_area("Assessment JSON")
    if assessment_path and not raw_json:
        try:
            raw_json = Path(assessment_path).read_text(encoding="utf-8")
        except OSError as exc:
            st.error(f"Unable to read assessment JSON: {exc}")
    assessment, authorization_note, load_error = load_dashboard_assessment_json(raw_json)
    if not assessment and workflow_assessment:
        assessment = workflow_assessment
        authorization_note = workflow_assessment.authorization_note
    if load_error and not workflow_assessment:
        st.warning(load_error)

    status = summarize_assessment_status(assessment, target, authorization_note=authorization_note)
    st.subheader("Assessment status")
    st.json(sanitize_dashboard_display_data(status))

    confirmed = st.checkbox("I confirm this assessment is authorized and in-scope")
    safe_live = st.checkbox("Enable safe-live passive recon")
    allow_network = st.checkbox("Allow limited network actions")
    audit_log_path = st.text_input("Audit log path")
    timeout_seconds = st.number_input("Timeout seconds", min_value=0.1, max_value=30.0, value=5.0)
    rate_limit_per_second = st.number_input("Rate limit per second", min_value=0.1, max_value=5.0, value=1.0)
    scan_budget = st.number_input("Scan budget", min_value=1, max_value=50, value=8, step=1)

    reasons = safe_live_gate_reasons(
        assessment=assessment,
        target=target,
        confirmed=confirmed,
        safe_live=safe_live,
        allow_network=allow_network,
        audit_log_path=audit_log_path,
    )
    if reasons:
        st.warning("Run Safe-Live Scan is disabled: " + "; ".join(reasons))
    can_run = not reasons
    if st.button("Run Safe-Live Scan", disabled=not can_run):
        assert assessment is not None
        policy = build_dashboard_live_config(
            safe_live=safe_live,
            allow_network=allow_network,
            confirmed=confirmed,
            audit_log_path=audit_log_path,
            timeout_seconds=float(timeout_seconds),
            rate_limit_per_second=float(rate_limit_per_second),
            scan_budget=int(scan_budget),
        )
        result = run_safe_live_from_dashboard(target=target, assessment=assessment, policy=policy)
        if audit_log_path:
            result.audit_events.extend(read_audit_log(audit_log_path))
        result.metadata["execution_context"] = sanitize_dashboard_display_data(asdict(policy))
        st.session_state["last_scan_result"] = result

    result = st.session_state.get("last_scan_result")
    if result:
        _render_scan_result(st, result)
    _render_export_buttons(st, result)


def render_streamlit() -> None:
    try:
        import streamlit as st
    except ImportError:
        print(build_streamlit_missing_message())
        return

    _render_copilot_workspace(st)


if __name__ == "__main__":
    render_streamlit()
