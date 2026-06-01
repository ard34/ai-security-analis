from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from core.assessment import Assessment
from core.finding_dedup import deduplicate_findings
from core.logging import read_audit_log
from core.models import ScanResult
from core.pipeline_domain import run_domain_assessment
from core.pipeline_source import run_source_assessment
from core.policies import DomainRunPolicy, redact_value
from core.scope import ScopeError
from reporting.html_report import render_html_report
from reporting.pdf_report import render_pdf_report

TYPE1_MODE = "Type 1 — Source Folder Assessment"
TYPE2_MODE = "Type 2 — Domain Safe-Live Assessment"


def mode_options() -> list[str]:
    return [TYPE1_MODE, TYPE2_MODE]


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
    note = data.get("authorization_note") or data.get("authorization") or data.get("note")
    return assessment, str(note) if note else None, None


def summarize_assessment_status(
    assessment: Assessment | None,
    target: str = "",
    *,
    authorization_note: str | None = None,
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "approved": bool(assessment and assessment.approved),
        "allowed_scope": list(assessment.allowed_targets) if assessment else [],
        "target_in_scope": False,
        "authorization_note": redact_value("authorization_note", authorization_note or ""),
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
    if st.button("Run Source Assessment") and source_path:
        st.session_state["last_scan_result"] = run_source_assessment(source_path)
    result = st.session_state.get("last_scan_result")
    if result:
        _render_scan_result(st, result)
    _render_export_buttons(st, result)


def _render_type2(st: Any) -> None:
    target = st.text_input("Target domain")
    assessment_path = st.text_input("Assessment JSON path")
    raw_json = st.text_area("Assessment JSON")
    if assessment_path and not raw_json:
        try:
            raw_json = Path(assessment_path).read_text(encoding="utf-8")
        except OSError as exc:
            st.error(f"Unable to read assessment JSON: {exc}")
    assessment, authorization_note, load_error = load_dashboard_assessment_json(raw_json)
    if load_error:
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
        return

    st.title("AI Security Analyst")
    mode = st.selectbox("Mode", mode_options())
    if mode == TYPE1_MODE:
        _render_type1(st)
    else:
        _render_type2(st)


if __name__ == "__main__":
    render_streamlit()
