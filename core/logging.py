from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SUPPORTED_AUDIT_EVENT_TYPES = {
    "scan_started",
    "scan_completed",
    "scan_rejected",
    "scan_failed",
    "report_exported",
    "json_imported",
    "json_exported",
    "history_saved",
    "history_loaded",
    "config_loaded",
    "dashboard_action",
    "cli_action",
    "validation_failed",
    "error",
}

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set-cookie",
    "session",
    "bearer",
    "credential",
    "private_key",
}

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class AuditEvent:
    event_type: str
    message: str
    scan_id: str | None = None
    target: str | None = None
    status: str | None = None
    actor: str = "local_user"
    source: str = "application"
    metadata: dict[str, Any] | None = None
    created_at: str | None = None


def _is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return normalized in {item.replace("-", "_") for item in SENSITIVE_KEYS}


def _redact_string(value: str) -> str:
    redacted = re.sub(
        r"(?i)(Authorization\s*:\s*Bearer\s+)([^\s,;]+)",
        rf"\1{REDACTED}",
        value,
    )
    redacted = re.sub(
        r"(?i)\b(api[_-]?key|token|session|secret|password|passwd|credential)=([^&\s,;]+)",
        rf"\1={REDACTED}",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]+)",
        rf"\1{REDACTED}",
        redacted,
    )
    return redacted


def redact_sensitive_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: REDACTED if _is_sensitive_key(key) else redact_sensitive_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _validate_event_type(event_type: str) -> None:
    if event_type not in SUPPORTED_AUDIT_EVENT_TYPES:
        raise ValueError(f"Unsupported audit event type: {event_type}")


def create_audit_event(
    event_type: str,
    message: str,
    scan_id: str | None = None,
    target: str | None = None,
    status: str | None = None,
    actor: str = "local_user",
    source: str = "application",
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    _validate_event_type(event_type)
    return AuditEvent(
        event_type=event_type,
        message=redact_sensitive_data(message),
        scan_id=redact_sensitive_data(scan_id),
        target=redact_sensitive_data(target),
        status=redact_sensitive_data(status),
        actor=redact_sensitive_data(actor),
        source=redact_sensitive_data(source),
        metadata=redact_sensitive_data(metadata) if metadata is not None else None,
        created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    )


def audit_event_to_dict(event: AuditEvent) -> dict[str, Any]:
    return redact_sensitive_data(asdict(event))


def audit_event_to_json_line(event: AuditEvent) -> str:
    return json.dumps(audit_event_to_dict(event), ensure_ascii=False, sort_keys=True) + "\n"


def write_audit_event(event: AuditEvent, log_path: str | Path) -> str:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(audit_event_to_json_line(event))
    return str(path)


def read_audit_events(log_path: str | Path, limit: int = 100) -> list[dict[str, Any]]:
    path = Path(log_path)
    if not path.exists():
        return []
    safe_limit = min(1000, max(1, int(limit or 100)))
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if len(events) >= safe_limit:
                break
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                events.append(redact_sensitive_data(parsed))
    return events


def get_app_logger(name: str = "ai_security_analyst") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
    return logger
