from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.logging import redact_sensitive_data
from core.pipeline import run_dummy_pipeline
from reporting.html_report import generate_html_report
from storage.json_io import scan_result_from_json_bytes, scan_result_to_json_bytes
from storage.repositories import ScanResultRepository


SUPPORTED_INTENTS = {
    "create_assessment",
    "approve_assessment",
    "run_dummy_scan",
    "analyze_scan_result",
    "generate_report",
    "export_json",
    "import_json",
    "show_history",
    "manual_testing_guidance",
    "unsafe_request",
    "unknown",
}

UNSAFE_PHRASES = (
    "exploit",
    "brute force",
    "bruteforce",
    "ddos",
    " dos",
    "credential theft",
    "steal cookie",
    "bypass login",
    "bypass authentication",
    "reverse shell",
    "shell",
    "persistence",
    "malware",
    "dropper",
    "ransomware",
    "sqlmap aggressive",
    "nmap aggressive",
    "fuzz all endpoints",
    "attack public target",
    "payload destructive",
    "destructive payload",
)


@dataclass(frozen=True)
class ToolRequest:
    intent: str
    arguments: dict[str, Any]
    requires_approval: bool = False


@dataclass(frozen=True)
class ToolResponse:
    success: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _normalized_message(user_message: str) -> str:
    return f" {str(user_message or '').strip().lower()} "


def is_unsafe_user_request(user_message: str) -> bool:
    text = _normalized_message(user_message)
    return any(phrase in text for phrase in UNSAFE_PHRASES)


def classify_intent(user_message: str) -> str:
    text = _normalized_message(user_message)
    if is_unsafe_user_request(user_message):
        return "unsafe_request"
    if "buat assessment" in text or "create assessment" in text:
        return "create_assessment"
    if "approve" in text or "setujui assessment" in text:
        return "approve_assessment"
    if "analisis hasil" in text or "analyze result" in text:
        return "analyze_scan_result"
    if "dummy scan" in text or "run scan" in text or " scan " in text:
        return "run_dummy_scan"
    if "export json" in text:
        return "export_json"
    if "import json" in text:
        return "import_json"
    if "history" in text or "riwayat" in text:
        return "show_history"
    if "manual testing" in text or "test case" in text or "rekomendasi pengujian" in text:
        return "manual_testing_guidance"
    if "report" in text or "laporan" in text:
        return "generate_report"
    return "unknown"


def build_tool_request(intent: str, arguments: dict[str, Any] | None = None) -> ToolRequest:
    if intent not in SUPPORTED_INTENTS:
        intent = "unknown"
    return ToolRequest(intent=intent, arguments=redact_sensitive_data(arguments or {}), requires_approval=intent == "run_dummy_scan")


def _context_scan_result(context: dict[str, Any]) -> dict[str, Any] | None:
    scan_result = context.get("scan_result")
    return scan_result if isinstance(scan_result, dict) else None


def _route_run_dummy_scan(request: ToolRequest, context: dict[str, Any]) -> ToolResponse:
    arguments = request.arguments
    target = str(arguments.get("target") or context.get("target") or "")
    allowed_domains = arguments.get("allowed_domains") or context.get("allowed_domains") or []
    allowed_ips = arguments.get("allowed_ips") or context.get("allowed_ips") or []
    scan_mode = str(arguments.get("scan_mode") or context.get("scan_mode") or "safe")
    if not target:
        return ToolResponse(False, "Target is required for dummy scan.", error="missing_target")
    if not isinstance(allowed_domains, list):
        return ToolResponse(False, "allowed_domains must be a list.", error="invalid_scope")
    result = run_dummy_pipeline(target=target, allowed_domains=allowed_domains, allowed_ips=allowed_ips, scan_mode=scan_mode)
    return ToolResponse(
        True,
        "Safe dummy scan completed locally. No live scanner or external command was executed.",
        data={"scan_result": redact_sensitive_data(result)},
    )


def route_tool_request(request: ToolRequest, context: dict[str, Any]) -> ToolResponse:
    safe_context = redact_sensitive_data(context or {})
    if request.intent == "unsafe_request":
        return ToolResponse(False, "Unsafe request refused.", error="unsafe_request")
    if request.intent == "unknown":
        return ToolResponse(
            False,
            "Please clarify a safe action: create assessment, run dummy scan, analyze result, report, JSON import/export, history, or manual testing guidance.",
            error="unknown_intent",
        )
    if request.intent == "run_dummy_scan":
        return _route_run_dummy_scan(request, safe_context)
    if request.intent == "analyze_scan_result":
        scan_result = _context_scan_result(safe_context)
        findings = scan_result.get("findings", []) if scan_result else []
        return ToolResponse(True, "Scan result analyzed locally.", data={"findings_count": len(findings), "findings": findings})
    if request.intent == "generate_report":
        scan_result = _context_scan_result(safe_context)
        if not scan_result:
            return ToolResponse(False, "A scan_result is required to generate a report.", error="missing_scan_result")
        return ToolResponse(True, "HTML report generated in memory.", data={"html": generate_html_report(scan_result)})
    if request.intent == "export_json":
        scan_result = _context_scan_result(safe_context)
        if not scan_result:
            return ToolResponse(False, "A scan_result is required to export JSON.", error="missing_scan_result")
        return ToolResponse(True, "JSON export payload generated in memory.", data={"json_bytes": scan_result_to_json_bytes(scan_result)})
    if request.intent == "import_json":
        raw = request.arguments.get("json_bytes") or safe_context.get("json_bytes")
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if not isinstance(raw, bytes):
            return ToolResponse(False, "json_bytes is required to import JSON.", error="missing_json_bytes")
        return ToolResponse(True, "JSON scan result imported from bytes.", data={"scan_result": scan_result_from_json_bytes(raw)})
    if request.intent == "show_history":
        db_path = request.arguments.get("db_path") or safe_context.get("db_path")
        limit = int(request.arguments.get("limit") or safe_context.get("limit") or 20)
        repository = ScanResultRepository(db_path) if db_path else ScanResultRepository()
        return ToolResponse(True, "Scan history loaded locally.", data={"history": repository.list_scan_results(limit=limit)})
    if request.intent == "manual_testing_guidance":
        findings = request.arguments.get("findings") or safe_context.get("findings") or []
        return ToolResponse(True, "Manual testing guidance can be generated from provided potential findings.", data={"findings": findings})
    if request.intent in {"create_assessment", "approve_assessment"}:
        return ToolResponse(True, "Assessment action should be handled by the assessment model.", data={"intent": request.intent})
    return ToolResponse(False, "Unsupported safe tool request.", error="unsupported_intent")
