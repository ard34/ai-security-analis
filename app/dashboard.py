from __future__ import annotations

from ui.app import (
    can_approve_assessment_from_ui,
    can_archive_assessment_from_ui,
    can_enable_domain_mode,
    can_export_dashboard_result,
    can_run_domain_scan_for_assessment,
    can_run_safe_live_from_dashboard,
    mode_options,
    render_streamlit,
    safe_live_gate_reasons,
    summarize_assessment_project,
)


def dashboard_modes() -> list[str]:
    return mode_options()


def domain_mode_enabled(assessment, confirmed: bool) -> bool:
    return can_enable_domain_mode(assessment, confirmed)


def dashboard_safe_live_enabled(
    *,
    assessment,
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


def dashboard_safe_live_reasons(
    *,
    assessment,
    target: str,
    confirmed: bool,
    safe_live: bool,
    allow_network: bool,
    audit_log_path: str | None,
) -> list[str]:
    return safe_live_gate_reasons(
        assessment=assessment,
        target=target,
        confirmed=confirmed,
        safe_live=safe_live,
        allow_network=allow_network,
        audit_log_path=audit_log_path,
    )


def dashboard_export_enabled(last_scan_result) -> bool:
    return can_export_dashboard_result(last_scan_result)


def dashboard_assessment_summary(assessment):
    return summarize_assessment_project(assessment)


def dashboard_can_approve_assessment(assessment) -> bool:
    return can_approve_assessment_from_ui(assessment)


def dashboard_can_archive_assessment(assessment) -> bool:
    return can_archive_assessment_from_ui(assessment)


def dashboard_can_run_domain_scan_for_assessment(
    *,
    assessment,
    target: str,
    confirmed: bool,
    safe_live: bool,
    allow_network: bool,
    audit_log_path: str | None,
) -> bool:
    return can_run_domain_scan_for_assessment(
        assessment=assessment,
        target=target,
        confirmed=confirmed,
        safe_live=safe_live,
        allow_network=allow_network,
        audit_log_path=audit_log_path,
    )


if __name__ == "__main__":
    render_streamlit()
