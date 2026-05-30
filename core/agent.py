from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.assessment import AssessmentProject, assessment_project_to_dict, is_assessment_approved
from core.logging import redact_sensitive_data
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
        guidance = generate_manual_testing_guidance(findings if isinstance(findings, list) else [])
        return AgentResponse(True, intent, "Manual testing guidance generated for potential findings.", {"guidance": guidance})

    if intent == "generate_report":
        tool_response = route_tool_request(build_tool_request(intent), safe_context)
        if tool_response.success:
            return AgentResponse(True, intent, tool_response.message, tool_response.data)
        return AgentResponse(True, intent, "Report generation is available when a local scan_result is provided.", {"next_step": "Provide scan_result in context."})

    if intent in {"analyze_scan_result", "export_json", "import_json", "show_history"}:
        tool_response = route_tool_request(build_tool_request(intent, safe_context), safe_context)
        return AgentResponse(tool_response.success, intent, tool_response.message, tool_response.data, tool_response.error)

    if intent in {"create_assessment", "approve_assessment"}:
        return AgentResponse(True, intent, "Use the assessment project model to perform this assessment workflow step.")

    return AgentResponse(False, intent, "This request is recognized but not implemented in the local orchestrator yet.")


def generate_manual_testing_guidance(findings: list[dict]) -> list[dict]:
    guidance: list[dict[str, Any]] = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        module = str(finding.get("module") or "").lower()
        title = str(finding.get("title") or "Potential finding")
        severity = str(finding.get("severity") or "low").lower()
        evidence = str(finding.get("evidence") or "")
        if module == "security_headers" or "header" in title.lower():
            area = "Security Headers"
            manual_test = "Review whether the missing header materially increases browser-side risk based on actual application behavior and injection points."
        else:
            area = title
            manual_test = "Review the evidence, reproduce safely inside the approved environment, and document whether the risk is valid."
        guidance.append(
            redact_sensitive_data(
                {
                    "area": area,
                    "priority": severity,
                    "manual_test": manual_test,
                    "evidence": evidence,
                    "validation_status": "needs_manual_validation",
                }
            )
        )
    if not guidance:
        guidance.append(
            {
                "area": "Assessment Planning",
                "priority": "info",
                "manual_test": "Review available assets, endpoints, and potential findings before selecting manual validation tasks.",
                "evidence": "No potential findings were provided.",
                "validation_status": "needs_manual_validation",
            }
        )
    return guidance


def summarize_agent_capabilities() -> str:
    return (
        "AI Security Analyst can create and approve assessment context, run the local dummy scan, analyze potential findings, "
        "generate report workflows, export/import local data, produce manual testing guidance, show history, and reject unsafe requests."
    )
