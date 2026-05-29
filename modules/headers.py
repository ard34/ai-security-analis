from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from core.models import Finding


MODULE_NAME = "security_headers"
SOURCE_NAME = "headers_module"


@dataclass(frozen=True)
class HeaderRule:
    header: str
    title: str
    severity: str
    confidence: str
    recommendation: str
    https_only: bool = False


HEADER_RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        header="Content-Security-Policy",
        title="Missing Content-Security-Policy Header",
        severity="low",
        confidence="medium",
        recommendation="Implement a restrictive Content-Security-Policy header.",
    ),
    HeaderRule(
        header="Strict-Transport-Security",
        title="Missing Strict-Transport-Security Header",
        severity="low",
        confidence="medium",
        recommendation="Set Strict-Transport-Security for HTTPS responses after validating HTTPS coverage.",
        https_only=True,
    ),
    HeaderRule(
        header="X-Frame-Options",
        title="Missing X-Frame-Options Header",
        severity="low",
        confidence="medium",
        recommendation="Set X-Frame-Options to DENY or SAMEORIGIN, or enforce framing restrictions with CSP frame-ancestors.",
    ),
    HeaderRule(
        header="X-Content-Type-Options",
        title="Missing X-Content-Type-Options Header",
        severity="low",
        confidence="medium",
        recommendation="Set X-Content-Type-Options to nosniff.",
    ),
    HeaderRule(
        header="Referrer-Policy",
        title="Missing Referrer-Policy Header",
        severity="info",
        confidence="medium",
        recommendation="Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
    HeaderRule(
        header="Permissions-Policy",
        title="Missing Permissions-Policy Header",
        severity="info",
        confidence="medium",
        recommendation="Define a least-privilege Permissions-Policy for browser features.",
    ),
    HeaderRule(
        header="Cross-Origin-Opener-Policy",
        title="Missing Cross-Origin-Opener-Policy Header",
        severity="info",
        confidence="low",
        recommendation="Set Cross-Origin-Opener-Policy where compatible with application behavior.",
    ),
    HeaderRule(
        header="Cross-Origin-Resource-Policy",
        title="Missing Cross-Origin-Resource-Policy Header",
        severity="info",
        confidence="low",
        recommendation="Set Cross-Origin-Resource-Policy where compatible with resource sharing requirements.",
    ),
)


def _normalize_headers(headers: Mapping[str, object] | None) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in (headers or {}).items():
        header_name = str(key or "").strip().lower()
        if header_name:
            normalized[header_name] = str(value or "").strip()
    return normalized


def _missing_header_finding(target: str, asset: str, endpoint: str, rule: HeaderRule) -> Finding:
    return Finding(
        target=target,
        asset=asset,
        endpoint=endpoint,
        module=MODULE_NAME,
        finding_type="missing_header",
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        evidence=f"{rule.header} header not present.",
        recommendation=rule.recommendation,
        source=SOURCE_NAME,
        metadata={"header": rule.header},
    )


def analyze_security_headers(
    target: str,
    asset: str,
    headers: Mapping[str, object] | None,
    is_https: bool = True,
    endpoint: str = "/",
) -> list[Finding]:
    """Analyze provided HTTP response headers.

    This module is intentionally passive and local-only. It does not perform
    HTTP requests, scanning, exploitation, brute force, or denial-of-service.
    """

    normalized = _normalize_headers(headers)
    findings: list[Finding] = []

    for rule in HEADER_RULES:
        if rule.https_only and not is_https:
            continue
        if not normalized.get(rule.header.lower()):
            findings.append(_missing_header_finding(target, asset, endpoint, rule))

    return findings
