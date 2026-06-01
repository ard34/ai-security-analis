from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "password",
    "secret",
}
SAFE_HTTP_METHODS = {"GET", "HEAD"}
PROHIBITED_ACTIONS = (
    "exploit",
    "brute force",
    "dos",
    "fuzz",
    "credential theft",
    "auth bypass",
    "active scanner",
)
SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)((api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;]+"),
]


class PolicyViolation(ValueError):
    pass


@dataclass(slots=True)
class DomainRunPolicy:
    safe_live: bool = False
    allow_network: bool = False
    confirm_safe_live: bool = False
    timeout_seconds: float = 5.0
    rate_limit_per_second: float = 1.0
    scan_budget: int = 8
    audit_log_path: str | None = None


def redact_value(key: str, value: Any) -> Any:
    if key.lower() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, str):
        redacted = value
        for pattern in SECRET_PATTERNS:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        return redacted
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, list):
        return [redact_value(key, item) for item in value]
    return value


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    return {key: redact_value(key, value) for key, value in data.items()}


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in redact_mapping(headers).items()
        if key.lower() not in {"authorization", "cookie", "set-cookie"}
    }


def require_type1_safe() -> None:
    return None


def require_safe_http_method(method: str) -> str:
    normalized = method.upper()
    if normalized not in SAFE_HTTP_METHODS:
        raise PolicyViolation("only safe HTTP GET/HEAD methods are allowed")
    return normalized


def require_domain_run_policy(policy: DomainRunPolicy, *, assessment_approved: bool) -> None:
    if not assessment_approved:
        raise PolicyViolation("assessment must be approved before live assessment")
    if not policy.safe_live:
        raise PolicyViolation("safe_live must be enabled")
    if not policy.allow_network:
        raise PolicyViolation("allow_network must be explicitly enabled")
    if not policy.confirm_safe_live:
        raise PolicyViolation("confirm_safe_live must be explicitly enabled")
    if not policy.audit_log_path:
        raise PolicyViolation("audit log path is required")
    if policy.timeout_seconds <= 0 or policy.timeout_seconds > 30:
        raise PolicyViolation("timeout must be between 0 and 30 seconds")
    if policy.rate_limit_per_second <= 0 or policy.rate_limit_per_second > 5:
        raise PolicyViolation("rate limit must be between 0 and 5 requests per second")
    if policy.scan_budget <= 0 or policy.scan_budget > 50:
        raise PolicyViolation("scan budget must be between 1 and 50")

