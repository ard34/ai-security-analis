from __future__ import annotations

from core.models import VALID_CONFIDENCES, VALID_SEVERITIES, Finding
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


def analyze(headers: dict[str, str] | None, is_https: bool = True) -> list[Finding]:
    return analyze_security_headers(
        target="example.com",
        asset="https://app.example.com",
        headers=headers,
        is_https=is_https,
        endpoint="/login",
    )


def titles(findings: list[Finding]) -> set[str]:
    return {finding.title for finding in findings}


def headers(findings: list[Finding]) -> set[str]:
    return {str(finding.metadata.get("header")) for finding in findings}


def test_missing_csp_generates_finding() -> None:
    input_headers = dict(COMPLETE_HEADERS)
    input_headers.pop("Content-Security-Policy")

    findings = analyze(input_headers)

    assert "Content-Security-Policy" in headers(findings)
    assert findings[0].finding_type == "missing_header"


def test_missing_hsts_on_https_generates_finding() -> None:
    input_headers = dict(COMPLETE_HEADERS)
    input_headers.pop("Strict-Transport-Security")

    findings = analyze(input_headers, is_https=True)

    assert "Strict-Transport-Security" in headers(findings)


def test_missing_hsts_on_http_does_not_generate_hsts_finding() -> None:
    input_headers = dict(COMPLETE_HEADERS)
    input_headers.pop("Strict-Transport-Security")

    findings = analyze(input_headers, is_https=False)

    assert "Strict-Transport-Security" not in headers(findings)
    assert findings == []


def test_complete_headers_generate_empty_list() -> None:
    assert analyze(COMPLETE_HEADERS) == []


def test_header_matching_is_case_insensitive() -> None:
    input_headers = {key.lower(): value for key, value in COMPLETE_HEADERS.items()}

    assert analyze(input_headers) == []


def test_empty_headers_do_not_crash() -> None:
    findings = analyze({})

    assert len(findings) == 8


def test_none_headers_do_not_crash() -> None:
    findings = analyze(None)

    assert len(findings) == 8


def test_all_findings_are_potential() -> None:
    assert all(finding.is_potential is True for finding in analyze({}))


def test_all_findings_have_valid_severity() -> None:
    assert all(finding.severity in VALID_SEVERITIES for finding in analyze({}))


def test_all_findings_have_valid_confidence() -> None:
    assert all(finding.confidence in VALID_CONFIDENCES for finding in analyze({}))


def test_missing_x_content_type_options_detected() -> None:
    input_headers = dict(COMPLETE_HEADERS)
    input_headers.pop("X-Content-Type-Options")

    assert "X-Content-Type-Options" in headers(analyze(input_headers))


def test_missing_referrer_policy_detected() -> None:
    input_headers = dict(COMPLETE_HEADERS)
    input_headers.pop("Referrer-Policy")

    assert "Referrer-Policy" in headers(analyze(input_headers))


def test_missing_permissions_policy_detected() -> None:
    input_headers = dict(COMPLETE_HEADERS)
    input_headers.pop("Permissions-Policy")

    assert "Permissions-Policy" in headers(analyze(input_headers))


def test_missing_coop_detected() -> None:
    input_headers = dict(COMPLETE_HEADERS)
    input_headers.pop("Cross-Origin-Opener-Policy")

    assert "Cross-Origin-Opener-Policy" in headers(analyze(input_headers))


def test_missing_corp_detected() -> None:
    input_headers = dict(COMPLETE_HEADERS)
    input_headers.pop("Cross-Origin-Resource-Policy")

    assert "Cross-Origin-Resource-Policy" in headers(analyze(input_headers))


def test_findings_use_security_headers_module() -> None:
    assert all(finding.module == "security_headers" for finding in analyze({}))


def test_findings_use_headers_module_source() -> None:
    assert all(finding.source == "headers_module" for finding in analyze({}))


def test_severity_and_confidence_are_not_aggressive() -> None:
    findings = analyze({})
    assert {finding.severity for finding in findings} <= {"info", "low"}
    assert {finding.confidence for finding in findings} <= {"low", "medium"}
