from __future__ import annotations

import re
from datetime import UTC, datetime

from core.models import VALIDATION_STATUSES, Finding
from core.policies import redact_value

UI_VALIDATION_STATUSES = [*sorted(VALIDATION_STATUSES), "needs_more_review"]
AI_ALLOWED_VALIDATION_STATUSES = {"potential", "logic_analyzed", "validation_ready"}
VALIDATION_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|cookie|session)\s*[:=]\s*)[^\s,;]+"),
]


def build_validation_status_options() -> list[str]:
    preferred = [
        "potential",
        "logic_analyzed",
        "validation_ready",
        "manually_confirmed",
        "false_positive",
        "accepted_risk",
        "needs_more_review",
    ]
    return [status for status in preferred if status in UI_VALIDATION_STATUSES]


def sanitize_validation_note(note: str) -> str:
    sanitized = str(redact_value("validation_note", note.strip()))
    for pattern in VALIDATION_SECRET_PATTERNS:
        sanitized = pattern.sub(r"\1[REDACTED]", sanitized)
    return sanitized


def can_mark_finding_manually_confirmed(*, reviewer: str, note: str, evidence_note: str) -> bool:
    return bool(reviewer.strip() and sanitize_validation_note(note) and sanitize_validation_note(evidence_note))


def update_finding_validation_status(
    finding: Finding,
    *,
    status: str,
    reviewer: str = "",
    note: str = "",
    evidence_note: str = "",
    actor: str = "manual",
) -> Finding:
    if status not in UI_VALIDATION_STATUSES:
        raise ValueError("invalid validation status")
    if actor != "manual" and status not in AI_ALLOWED_VALIDATION_STATUSES:
        raise ValueError("automated validation can only set analysis-ready statuses")
    if status == "manually_confirmed" and not can_mark_finding_manually_confirmed(
        reviewer=reviewer,
        note=note,
        evidence_note=evidence_note,
    ):
        raise ValueError("manual confirmation requires reviewer, note, and evidence")
    if status in {"false_positive", "accepted_risk", "needs_more_review"} and not sanitize_validation_note(note):
        raise ValueError("validation note is required")

    if status in VALIDATION_STATUSES:
        finding.validation_status = status
    else:
        finding.metadata["ui_validation_status"] = status
    finding.metadata["validation_update"] = {
        "status": status,
        "reviewer": sanitize_validation_note(reviewer),
        "note": sanitize_validation_note(note),
        "evidence_note": sanitize_validation_note(evidence_note),
        "actor": actor,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    return finding
