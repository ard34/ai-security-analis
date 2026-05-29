from __future__ import annotations

from agent.report.json_writer import read_json, write_json


def analyze_security_misconfigurations(output_path: str = "outputs/potential_security_misconfigurations.json") -> list[dict[str, object]]:
    findings = []
    headers = read_json("outputs/recon/security_headers.json", default=[]) or []
    checks = [("missing_csp", "CSP header missing"), ("missing_hsts", "HSTS header missing"), ("missing_x_frame_options", "X-Frame-Options missing"), ("missing_x_content_type_options", "X-Content-Type-Options missing")]
    for item in headers:
        if not isinstance(item, dict):
            continue
        for key, title in checks:
            if item.get(key):
                findings.append({"title": "Potential Security Misconfiguration", "type": "Security misconfiguration", "severity": "Low", "confidence": "High", "endpoint": item.get("url", ""), "affected_host": item.get("host", ""), "reason": title, "manual_test_focus": ["Cek header keamanan, CORS, cookie flags, debug mode, exposed server version."], "status": "Potential", "manual_validation_required": True, "owasp_web": "A05 Security Misconfiguration", "owasp_api": "API8 Security Misconfiguration"})
        if item.get("cors_notes"):
            findings.append({"title": "Potential Security Misconfiguration", "type": "Security misconfiguration", "severity": "Medium", "confidence": "Medium", "endpoint": item.get("url", ""), "affected_host": item.get("host", ""), "reason": item.get("cors_notes"), "manual_test_focus": ["Review CORS allowlist dan credential handling."], "status": "Potential", "manual_validation_required": True, "owasp_web": "A05 Security Misconfiguration", "owasp_api": "API8 Security Misconfiguration"})
    write_json(output_path, findings)
    return findings
