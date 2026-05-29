from __future__ import annotations

from agent.report.json_writer import read_json, write_json


def analyze_auth_session(output_path: str = "outputs/potential_auth_session_issues.json") -> list[dict[str, object]]:
    findings = []
    headers = read_json("outputs/recon/security_headers.json", default=[]) or []
    for item in headers:
        if not isinstance(item, dict):
            continue
        for issue in item.get("cookie_issues", []) if isinstance(item.get("cookie_issues"), list) else []:
            findings.append({"title": "Potential Authentication Weakness", "type": "Authentication/session weakness", "severity": "Low", "confidence": "Medium", "endpoint": item.get("url", ""), "affected_host": item.get("host", ""), "reason": issue, "manual_test_focus": ["Cek cookie flags, token di URL, CSRF, dan session invalidation."], "status": "Potential", "manual_validation_required": True, "owasp_web": "A07 Identification and Authentication Failures", "owasp_api": "API2 Broken Authentication"})
    endpoints = read_json("outputs/recon/important_endpoints.json", default=[]) or []
    for ep in endpoints:
        url = str(ep.get("url", "")) if isinstance(ep, dict) else ""
        if any(token in url.lower() for token in ["token=", "access_token=", "reset"]):
            findings.append({"title": "Potential Authentication Weakness", "type": "Authentication/session weakness", "severity": "Medium", "confidence": "Low", "endpoint": url, "affected_host": ep.get("hostname", "") if isinstance(ep, dict) else "", "reason": "Auth/token pattern membutuhkan review manual.", "manual_test_focus": ["Uji login/logout/reset password/session handling."], "status": "Potential", "manual_validation_required": True, "owasp_web": "A07 Identification and Authentication Failures", "owasp_api": "API2 Broken Authentication"})
    write_json(output_path, findings)
    return findings
