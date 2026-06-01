from __future__ import annotations

from core.models import ScanResult


def local_copilot_response(message: str, result: ScanResult | None = None) -> str:
    lowered = message.lower()
    if "finding" in lowered and result:
        return (
            f"There are {len(result.findings)} potential findings. "
            "Validate each manually before treating it as confirmed."
        )
    if "report" in lowered:
        return "Use the HTML, PDF, or JSON export actions. Reports are redacted and mark findings as potential."
    return "I can route local source assessments and gated safe-live domain assessments. No external LLM API is used."

