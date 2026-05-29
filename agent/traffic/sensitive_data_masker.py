from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "set-cookie",
    "csrf",
    "xsrf",
    "email",
    "api_key",
    "secret",
}


def _is_sensitive(key: str) -> bool:
    lower = key.lower()
    return any(sensitive in lower for sensitive in SENSITIVE_KEYS)


def mask_sensitive_data(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _is_sensitive(str(key)) else mask_sensitive_data(item) for key, item in value.items()}
    if isinstance(value, list):
        return [mask_sensitive_data(item) for item in value]
    if isinstance(value, str):
        masked = value
        for key in SENSITIVE_KEYS:
            masked = re.sub(rf"({re.escape(key)}\s*[:=]\s*)[^&\s\"']+", r"\1[REDACTED]", masked, flags=re.I)
        masked = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[REDACTED]", masked)
        return masked
    return value
