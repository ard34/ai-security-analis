from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.assessment import AssessmentProject, assessment_project_to_dict, is_assessment_approved
from core.evidence import collect_evidence_from_scan_result, summarize_evidence
from core.finding_dedup import deduplicate_findings, deduped_findings_to_dicts, summarize_deduped_findings
from core.logging import redact_sensitive_data
from core.manual_testing import (
    generate_manual_testing_recommendations,
    manual_test_recommendation_to_dict,
    summarize_manual_testing_recommendations,
)
from core.prompts import build_refusal_message
from core.tool_router import build_tool_request, classify_intent, is_unsafe_user_request, route_tool_request


APPROVAL_REQUIRED_INTENTS = {"run_dummy_scan"}


@dataclass
class AgentResponse:
    success: bool
    intent: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    refusal_reason: str | None = None

    def __post_init__(self) -> None:
        self.message = str(redact_sensitive_data(self.message))
        self.data = redact_sensitive_data(dict(self.data or {}))
        self.refusal_reason = redact_sensitive_data(self.refusal_reason) if self.refusal_reason else None


def _project_context(project: AssessmentProject) -> dict[str, Any]:
    project_data = assessment_project_to_dict(project)
    return {
        "project": project_data,
        "allowed_domains": project.scope.allowed_domains,
        "allowed_ips": project.scope.allowed_ips,
        "scan_mode": project.scan_mode,
    }


def _requires_approved_assessment(intent: str) -> bool:
    return intent in APPROVAL_REQUIRED_INTENTS


def analyze_user_request(
    user_message: str,
    project: AssessmentProject | None = None,
    context: dict[str, Any] | None = None,
) -> AgentResponse:
    message = str(user_message or "").strip()
    safe_context = redact_sensitive_data(context or {})
    if not message:
        return AgentResponse(False, "unknown", "Please provide a safe assessment request.")
    if is_unsafe_user_request(message):
        reason = "it asks for activity outside authorized defensive assessment boundaries"
        return AgentResponse(False, "unsafe_request", build_refusal_message(reason), refusal_reason=reason)

    intent = classify_intent(message)
    if intent == "unsafe_request":
        reason = "the request matches unsafe activity patterns"
        return AgentResponse(False, intent, build_refusal_message(reason), refusal_reason=reason)
    if intent == "unknown":
        return AgentResponse(
            False,
            intent,
            "Please choose a safe action: create assessment, approve assessment, run dummy scan, analyze result, generate report, import/export JSON, show history, or manual testing guidance.",
        )
    if _requires_approved_assessment(intent):
        if project is None:
            return AgentResponse(False, intent, "An assessment project is required before running a dummy scan.")
        if not is_assessment_approved(project):
            return AgentResponse(False, intent, "The assessment must be approved before any scan action can run.")

    if intent == "run_dummy_scan":
        assert project is not None
        arguments = {
            "target": safe_context.get("target") or project.scope.allowed_domains[0] if project.scope.allowed_domains else "",
            "allowed_domains": project.scope.allowed_domains,
            "allowed_ips": project.scope.allowed_ips,
            "scan_mode": project.scan_mode,
        }
        tool_response = route_tool_request(build_tool_request(intent, arguments), {**safe_context, **_project_context(project)})
        return AgentResponse(tool_response.success, intent, tool_response.message, tool_response.data, tool_response.error)

    if intent == "manual_testing_guidance":
        findings = safe_context.get("findings") or []
        if not findings and isinstance(safe_context.get("scan_result"), dict):
            findings = safe_context["scan_result"].get("findings", [])
        recommendations = generate_manual_testing_recommendations(findings if isinstance(findings, list) else [])
        recommendation_dicts = [manual_test_recommendation_to_dict(item) for item in recommendations]
        return AgentResponse(
            True,
            intent,
            "Manual testing recommendations generated for authorized, non-destructive validation.",
            {
                "guidance": recommendation_dicts,
                "recommendations": recommendation_dicts,
                "summary": summarize_manual_testing_recommendations(recommendations),
            },
        )

    if intent == "generate_report":
        tool_response = route_tool_request(build_tool_request(intent), safe_context)
        if tool_response.success:
            return AgentResponse(True, intent, tool_response.message, tool_response.data)
        return AgentResponse(True, intent, "Report generation is available when a local scan_result is provided.", {"next_step": "Provide scan_result in context."})

    if intent == "analyze_scan_result":
        scan_result = safe_context.get("scan_result") if isinstance(safe_context.get("scan_result"), dict) else {}
        findings = _scan_result_findings(scan_result)
        evidence_items = collect_evidence_from_scan_result(scan_result)
        deduped = deduplicate_findings(findings, evidence_items=evidence_items)
        summary = {
            "evidence": summarize_evidence(evidence_items),
            "findings_before_dedup": len(findings),
            "unique_findings": len(deduped),
            "dedup_summary": summarize_deduped_findings(deduped),
            "priority_findings": deduped_findings_to_dicts(deduped[:5]),
            "validation_status": "needs_manual_validation",
        }
        return AgentResponse(True, intent, "Local scan result analyzed with evidence collection and finding deduplication.", summary)

    if intent in {"export_json", "import_json", "show_history"}:
        tool_response = route_tool_request(build_tool_request(intent, safe_context), safe_context)
        return AgentResponse(tool_response.success, intent, tool_response.message, tool_response.data, tool_response.error)

    if intent in {"create_assessment", "approve_assessment"}:
        return AgentResponse(True, intent, "Use the assessment project model to perform this assessment workflow step.")

    return AgentResponse(False, intent, "This request is recognized but not implemented in the local orchestrator yet.")


def _scan_result_findings(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in (scan_result or {}).get("findings") or []:
        if isinstance(finding, dict):
            findings.append(dict(finding))
        elif hasattr(finding, "to_dict"):
            findings.append(finding.to_dict())
        elif hasattr(finding, "__dict__"):
            findings.append(dict(finding.__dict__))
    return redact_sensitive_data(findings)


def generate_manual_testing_guidance(findings: list[dict]) -> list[dict]:
    guidance: list[dict[str, Any]] = []
    for item in generate_manual_testing_recommendations(findings):
        guidance.append(
            redact_sensitive_data(
                {
                    "area": item.area,
                    "priority": item.priority,
                    "manual_test": item.manual_steps[0] if item.manual_steps else "Review available evidence safely.",
                    "evidence": ", ".join(item.evidence_refs) if item.evidence_refs else item.description,
                    "validation_status": item.validation_status,
                }
            )
        )
    return guidance


def summarize_agent_capabilities() -> str:
    return (
        "AI Security Analyst can create and approve assessment context, run the local dummy scan, analyze potential findings, "
        "generate report workflows, export/import local data, produce manual testing guidance, show history, and reject unsafe requests."
    )
