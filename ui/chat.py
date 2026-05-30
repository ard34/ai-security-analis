from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any
import re

from core.agent import AgentResponse, analyze_user_request
from core.logging import redact_sensitive_data


VALID_CHAT_ROLES = {"user", "assistant", "system"}
DEFAULT_GREETING = (
    "I can help with authorized assessment planning, safe dummy analysis, local result review, "
    "manual testing guidance, and report workflow preparation. I will refuse unsafe requests."
)


def sanitize_chat_message(message: str) -> str:
    text = str(message or "").strip()
    text = str(redact_sensitive_data(text))
    text = re.sub(r"(?i)(Cookie\s*:\s*)([^\n\r]+)", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(Set-Cookie\s*:\s*)([^\n\r]+)", r"\1[REDACTED]", text)
    return text


def append_chat_message(history: list[dict], role: str, content: str) -> list[dict]:
    safe_role = str(role or "").strip().lower()
    if safe_role not in VALID_CHAT_ROLES:
        raise ValueError(f"Invalid chat role: {role}")
    safe_history = initialize_chat_history(history) if history else []
    safe_history.append({"role": safe_role, "content": sanitize_chat_message(content)})
    return safe_history


def initialize_chat_history(existing: list[dict] | None = None) -> list[dict]:
    if existing is None:
        return [{"role": "assistant", "content": DEFAULT_GREETING}]
    safe_history: list[dict] = []
    for item in existing:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip().lower()
        if role not in VALID_CHAT_ROLES:
            continue
        safe_history.append({"role": role, "content": sanitize_chat_message(str(item.get("content") or ""))})
    return safe_history


def _safe_session_value(value: Any) -> Any:
    if is_dataclass(value):
        return redact_sensitive_data(asdict(value))
    if isinstance(value, dict):
        return redact_sensitive_data(value)
    return redact_sensitive_data(value)


def build_agent_context_from_session(session_state: dict) -> dict:
    session = session_state if isinstance(session_state, dict) else {}
    context: dict[str, Any] = {}
    if "active_assessment" in session:
        context["active_assessment"] = _safe_session_value(session["active_assessment"])
    if "last_scan_result" in session:
        context["scan_result"] = _safe_session_value(session["last_scan_result"])
    if "selected_scan_id" in session:
        context["selected_scan_id"] = sanitize_chat_message(str(session["selected_scan_id"]))
    return redact_sensitive_data(context)


def _response_to_dict(response: AgentResponse | dict[str, Any]) -> dict[str, Any]:
    if isinstance(response, AgentResponse):
        return {
            "success": response.success,
            "intent": response.intent,
            "message": response.message,
            "data": response.data,
            "refusal_reason": response.refusal_reason,
        }
    payload = response if isinstance(response, dict) else {}
    return {
        "success": bool(payload.get("success", False)),
        "intent": str(payload.get("intent") or "unknown"),
        "message": sanitize_chat_message(str(payload.get("message") or "")),
        "data": redact_sensitive_data(payload.get("data") if isinstance(payload.get("data"), dict) else {}),
        "refusal_reason": sanitize_chat_message(str(payload.get("refusal_reason") or "")) or None,
    }


def handle_chat_turn(
    user_message: str,
    chat_history: list[dict],
    project=None,
    context: dict | None = None,
) -> tuple[list[dict], dict]:
    safe_user_message = sanitize_chat_message(user_message)
    history = append_chat_message(chat_history, "user", safe_user_message)
    response = analyze_user_request(safe_user_message, project=project, context=redact_sensitive_data(context or {}))
    response_dict = _response_to_dict(response)
    history = append_chat_message(history, "assistant", format_agent_response_for_chat(response_dict))
    return history, response_dict


def format_agent_response_for_chat(response) -> str:
    payload = _response_to_dict(response)
    message = sanitize_chat_message(payload["message"])
    lines = [message]
    if payload.get("refusal_reason"):
        lines.append(f"\nRefusal reason: {sanitize_chat_message(str(payload['refusal_reason']))}")
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    if data:
        summary_parts: list[str] = []
        if isinstance(data.get("scan_result"), dict):
            result = data["scan_result"]
            summary_parts.append(
                f"Scan status: {result.get('status', 'unknown')} | Findings: {len(result.get('findings') or [])}"
            )
        if isinstance(data.get("guidance"), list):
            summary_parts.append(f"Manual guidance items: {len(data['guidance'])}")
        if isinstance(data.get("findings"), list):
            summary_parts.append(f"Findings: {len(data['findings'])}")
        if data.get("next_step"):
            summary_parts.append(f"Next step: {data['next_step']}")
        if summary_parts:
            lines.append("\n" + "\n".join(f"- {sanitize_chat_message(item)}" for item in summary_parts))
    return "\n".join(lines)
