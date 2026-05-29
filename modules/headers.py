from __future__ import annotations

from typing import Mapping
from urllib.parse import urlparse

from core.models import Finding


SECURITY_HEADERS: dict[str, dict[str, str]] = {
    "content-security-policy": {
        "finding_type": "missing_csp",
        "title": "Missing Content-Security-Policy Header",
        "recommendation": "Implement a restrictive Content-Security-Policy header.",
    },
    "x-frame-options": {
        "finding_type": "missing_x_frame_options",
        "title": "Missing X-Frame-Options Header",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN, or use frame-ancestors in CSP.",
    },
    "x-content-type-options": {
        "finding_type": "missing_x_content_type_options",
        "title": "Missing X-Content-Type-Options Header",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "referrer-policy": {
        "finding_type": "missing_referrer_policy",
        "title": "Missing Referrer-Policy Header",
        "recommendation": "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin.",
    },
    "permissions-policy": {
        "finding_type": "missing_permissions_policy",
        "title": "Missing Permissions-Policy Header",
        "recommendation": "Define a least-privilege Permissions-Policy for browser features.",
    },
    "cross-origin-opener-policy": {
        "finding_type": "missing_cross_origin_opener_policy",
        "title": "Missing Cross-Origin-Opener-Policy Header",
        "recommendation": "Set Cross-Origin-Opener-Policy where compatible with application behavior.",
    },
    "cross-origin-resource-policy": {
        "finding_type": "missing_cross_origin_resource_policy",
        "title": "Missing Cross-Origin-Resource-Policy Header",
        "recommendation": "Set Cross-Origin-Resource-Policy where compatible with resource sharing requirements.",
    },
}


HSTS_HEADER = "strict-transport-security"


def _normalize_headers(headers: Mapping[str, object] | None) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in (headers or {}).items():
        normalized[str(key).strip().lower()] = str(value or "").strip()
    return normalized


def _asset_from_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url


def _path_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path or "/"


def _is_https(url: str) -> bool:
    return urlparse(url).scheme.lower() == "https"


def _missing_header_finding(target: str, url: str, header_name: str, spec: dict[str, str]) -> Finding:
    canonical = "-".join(part.capitalize() for part in header_name.split("-"))
    return Finding(
        target=target,
        asset=_asset_from_url(url),
        endpoint=_path_from_url(url),
        module="security_headers",
        finding_type=spec["finding_type"],
        title=spec["title"],
        severity="low",
        confidence="high",
        evidence=f"{canonical} header not present.",
        recommendation=spec["recommendation"],
        source="headers_module",
    )


def analyze_security_headers(headers: Mapping[str, object] | None, url: str, target: str | None = None) -> list[Finding]:
    """Analyze supplied response headers only.

    This function intentionally performs no network requests. Callers must pass
    headers captured elsewhere.
    """

    normalized = _normalize_headers(headers)
    parsed = urlparse(url)
    target_name = target or parsed.hostname or url
    findings: list[Finding] = []

    for header_name, spec in SECURITY_HEADERS.items():
        if not normalized.get(header_name):
            findings.append(_missing_header_finding(target_name, url, header_name, spec))

    if _is_https(url) and not normalized.get(HSTS_HEADER):
        findings.append(
            _missing_header_finding(
                target_name,
                url,
                HSTS_HEADER,
                {
                    "finding_type": "missing_hsts",
                    "title": "Missing Strict-Transport-Security Header",
                    "recommendation": "Set Strict-Transport-Security for HTTPS responses after validating HTTPS coverage.",
                },
            )
        )

    return findings

