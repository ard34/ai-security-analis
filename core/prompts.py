from __future__ import annotations

import json

from core.logging import redact_sensitive_data


SECURITY_ANALYST_SYSTEM_PROMPT = """
You are an Authorized Red Team Copilot for pre-production web/API security assessment.

Core rules:
- Work only on authorized targets and respect the approved assessment scope.
- Do not exploit, brute force, perform denial-of-service, steal credentials, or bypass authentication.
- Do not create destructive payloads or instructions for unauthorized access.
- Do not treat a vulnerability as confirmed without evidence.
- Treat every finding as potential until a human pentester manually validates it.
- Keep recommendations defensive, actionable, and aligned with internal security assessment work.
- Prefer evidence-based prioritization and manual validation guidance.
"""


def build_agent_context_prompt(project: dict, evidence: dict | None = None) -> str:
    safe_project = redact_sensitive_data(project or {})
    safe_evidence = redact_sensitive_data(evidence or {})
    return (
        "Assessment context for the authorized red team copilot.\n"
        f"Project:\n{json.dumps(safe_project, ensure_ascii=False, indent=2, sort_keys=True)}\n"
        f"Evidence:\n{json.dumps(safe_evidence, ensure_ascii=False, indent=2, sort_keys=True)}\n"
        "Use this context only for defensive planning and manual validation guidance."
    )


def build_refusal_message(reason: str) -> str:
    safe_reason = str(redact_sensitive_data(reason or "The request is outside the safe assessment boundaries."))
    return (
        f"I cannot help with that request because {safe_reason}. "
        "I can help with authorized scope review, passive analysis, prioritization, reporting, or safe manual validation guidance."
    )


def build_manual_testing_guidance_prompt(target: str, findings: list[dict]) -> str:
    safe_target = str(redact_sensitive_data(target or ""))
    safe_findings = redact_sensitive_data(findings or [])
    return (
        "Build defensive manual testing guidance for an authorized assessment.\n"
        f"Target: {safe_target}\n"
        f"Potential findings:\n{json.dumps(safe_findings, ensure_ascii=False, indent=2, sort_keys=True)}\n"
        "Do not provide exploit payloads. Mark every item as needing manual validation."
    )
