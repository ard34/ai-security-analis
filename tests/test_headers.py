from __future__ import annotations

from core.models import Finding
from modules.headers import analyze_security_headers


COMPLETE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def finding_types(findings: list[Finding]) -> set[str]:
    return {finding.finding_type for finding in findings}


def test_missing_headers_generate_potential_findings() -> None:
    findings = analyze_security_headers({}, "https://app.example.com/login")

    types = finding_types(findings)
    assert "missing_csp" in types
    assert "missing_hsts" in types
    assert "missing_x_frame_options" in types
    assert "missing_x_content_type_options" in types
    assert "missing_referrer_policy" in types
    assert "missing_permissions_policy" in types
    assert "missing_cross_origin_opener_policy" in types
    assert "missing_cross_origin_resource_policy" in types
    assert all(finding.is_potential for finding in findings)
    assert all(finding.module == "security_headers" for finding in findings)


def test_complete_headers_generate_no_findings() -> None:
    findings = analyze_security_headers(COMPLETE_HEADERS, "https://app.example.com/")
    assert findings == []


def test_headers_are_case_insensitive() -> None:
    headers = {key.lower(): value for key, value in COMPLETE_HEADERS.items()}
    headers["content-security-policy"] = "default-src 'self'"

    findings = analyze_security_headers(headers, "https://app.example.com/")

    assert findings == []


def test_empty_headers_do_not_crash() -> None:
    findings = analyze_security_headers(None, "https://app.example.com/")
    assert len(findings) == 8
    assert all(isinstance(finding, Finding) for finding in findings)


def test_hsts_is_required_for_https() -> None:
    headers = dict(COMPLETE_HEADERS)
    headers.pop("Strict-Transport-Security")

    findings = analyze_security_headers(headers, "https://app.example.com/")

    assert finding_types(findings) == {"missing_hsts"}


def test_hsts_is_not_required_for_http() -> None:
    headers = dict(COMPLETE_HEADERS)
    headers.pop("Strict-Transport-Security")

    findings = analyze_security_headers(headers, "http://app.example.com/")

    assert "missing_hsts" not in finding_types(findings)
    assert findings == []

