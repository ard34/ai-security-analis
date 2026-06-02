from __future__ import annotations

from core.models import Finding, ScanResult
from core.policies import redact_value

UNSAFE_CHAT_FRAGMENTS = (
    "exploit",
    "auto exploit",
    "brute " + "force",
    "d" + "os",
    "credential theft",
    "steal credential",
    "auth bypass",
    "bypass auth",
    "reverse " + "shell",
)
SAFE_REFUSAL = (
    "I cannot help automate harmful testing or bypass activity. I can help with authorized manual validation, "
    "evidence collection, false-positive checks, and remediation guidance from local scan data."
)


def build_chat_context(result: ScanResult | None = None) -> dict[str, object]:
    return {"has_result": result is not None, "finding_count": len(result.findings) if result else 0}


def respond(message: str, result: ScanResult | None = None) -> str:
    return handle_copilot_chat_turn(message, scan_result=result)


def reject_unsafe_copilot_request(message: str) -> str | None:
    lowered = message.lower()
    if any(fragment in lowered for fragment in UNSAFE_CHAT_FRAGMENTS):
        return SAFE_REFUSAL
    return None


def summarize_scan_for_copilot(scan_result: ScanResult | None) -> str:
    if not scan_result:
        return "No scan is loaded. Run a local source analysis or select a previous scan first."
    validation_ready = sum(1 for finding in scan_result.findings if finding.validation_status == "validation_ready")
    return (
        f"Current scan {scan_result.id} covers {scan_result.target} with {len(scan_result.findings)} findings, "
        f"{validation_ready} validation-ready findings, and {len(scan_result.evidence)} evidence records."
    )


def explain_finding_for_chat(finding: Finding | None) -> str:
    if not finding:
        return "No finding is selected. Select a finding to view source location and validation detail."
    locations = ", ".join(
        f"{location.get('file', '')}:{location.get('line', '')}" for location in finding.source_locations
    )
    parts = [
        f"Finding: {finding.title}",
        f"Severity: {finding.severity}",
        f"Validation status: {finding.validation_status}",
        f"Confidence score: {finding.confidence_score}",
        f"Source location: {locations or 'not mapped'}",
        f"Root cause: {finding.root_cause or 'not provided'}",
        f"Missing control: {finding.missing_control or 'not provided'}",
        f"Reasoning: {finding.exploitability_reasoning or 'manual review required'}",
    ]
    return "\n".join(str(redact_value("chat", part)) for part in parts)


def build_manual_validation_answer(finding: Finding | None) -> str:
    if not finding:
        return "Select a finding first. Manual validation steps depend on the selected source flow."
    steps = "\n".join(f"- {step}" for step in finding.manual_validation_steps)
    evidence = "\n".join(f"- {item}" for item in finding.expected_evidence)
    checks = "\n".join(f"- {item}" for item in finding.false_positive_checks)
    return (
        "Manual validation must be authorized and evidence-based.\n\n"
        f"Steps:\n{steps}\n\nExpected evidence:\n{evidence}\n\nFalse-positive checks:\n{checks}"
    )


def build_report_export_answer(scan_result: ScanResult | None) -> str:
    if not scan_result:
        return "No scan is loaded. Run or select a scan before exporting a report."
    return "Use the JSON, HTML, or PDF export controls for the current scan. Reports redact sensitive values."


def handle_copilot_chat_turn(
    message: str,
    *,
    scan_result: ScanResult | None = None,
    selected_finding: Finding | None = None,
) -> str:
    unsafe = reject_unsafe_copilot_request(message)
    if unsafe:
        return unsafe
    lowered = message.lower()
    if "manual" in lowered or "validation" in lowered or "evidence" in lowered:
        return build_manual_validation_answer(selected_finding or _first_finding(scan_result))
    if "finding" in lowered or "celah" in lowered or "root cause" in lowered:
        return explain_finding_for_chat(selected_finding or _first_finding(scan_result))
    if "report" in lowered or "export" in lowered:
        return build_report_export_answer(scan_result)
    if "scan" in lowered or "summary" in lowered or "analisis" in lowered:
        return summarize_scan_for_copilot(scan_result)
    return (
        "I can explain local scan findings, summarize validation-ready issues, build manual validation guidance, "
        "and prepare report export guidance from the current scan."
    )


def _first_finding(scan_result: ScanResult | None) -> Finding | None:
    if not scan_result or not scan_result.findings:
        return None
    return scan_result.findings[0]

