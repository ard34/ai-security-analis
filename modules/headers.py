from __future__ import annotations

RECOMMENDED_HEADERS = {
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "strict-transport-security",
}


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def analyze_security_headers(headers: dict[str, str]) -> list[str]:
    normalized = normalize_headers(headers)
    return sorted(header for header in RECOMMENDED_HEADERS if header not in normalized)

