from __future__ import annotations

from core.models import ScanResult
from core.policies import redact_value

UNSAFE_MESSAGE_FRAGMENTS = (
    "exploit",
    "brute " + "force",
    "d" + "os",
    "credential theft",
    "auth bypass",
)


def local_copilot_response(message: str, result: ScanResult | None = None) -> str:
    lowered = message.lower()
    if any(fragment in lowered for fragment in UNSAFE_MESSAGE_FRAGMENTS):
        return (
            "I cannot help automate harmful testing or bypass activity. I can help with authorized manual "
            "validation, evidence collection, false-positive checks, and remediation."
        )
    if "finding" in lowered and result:
        return (
            f"There are {len(result.findings)} potential findings. "
            "Validate each manually before treating it as confirmed."
        )
    if "evidence" in lowered and result:
        return str(redact_value("evidence", [item.to_dict() for item in result.evidence]))
    if "report" in lowered:
        return "Use the HTML, PDF, or JSON export actions. Reports are redacted and mark findings as potential."
    return "I can route local source assessments and gated safe-live domain assessments. No external LLM API is used."

