from __future__ import annotations

from core.models import Finding

SAFE_VALIDATION_SAFETY_NOTES = [
    "Use only written authorized scope and a staging or lab environment.",
    "Use browser, Burp, or Postman manually; do not automate high-volume testing.",
    "Do not access accounts, files, or records outside the approved test data set.",
]


def build_manual_validation_plan(finding: Finding) -> dict[str, object]:
    role = finding.attacker_model or "authorized tester with approved low-privilege and comparison accounts"
    return {
        "objective": f"Manually confirm whether the source-derived issue is reachable: {finding.title}",
        "required_roles": [role, "application owner or code owner for observation and approval"],
        "test_environment": "Approved staging, lab, or internal beta environment only.",
        "preconditions": finding.preconditions
        or [
            "Assessment scope and written authorization are confirmed.",
            "Two approved test identities or roles are available when access boundaries are involved.",
        ],
        "step_by_step": finding.manual_validation_steps,
        "expected_vulnerable_result": "The sensitive action or object access succeeds without the expected control.",
        "expected_secure_result": (
            "The application rejects the action or object access with an authorization-safe response."
        ),
        "evidence_to_collect": finding.expected_evidence,
        "false_positive_checks": finding.false_positive_checks,
        "cleanup_steps": [
            "Revert only test data changed during validation.",
            "Record timestamps, request identifiers, and reviewer notes in the assessment evidence.",
        ],
        "safety_notes": SAFE_VALIDATION_SAFETY_NOTES,
    }


def attach_manual_validation_plan(finding: Finding) -> Finding:
    finding.metadata["manual_validation_plan"] = build_manual_validation_plan(finding)
    return finding
