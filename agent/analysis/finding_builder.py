from __future__ import annotations

from agent.report.json_writer import read_json, write_json

QUEUE_TYPES = {
    "BOLA/IDOR",
    "BFLA",
    "Business logic flaw",
    "Injection indicator",
    "Authentication/session weakness",
    "Open redirect",
    "File access risk",
    "Sensitive data exposure",
    "Security misconfiguration",
    "Vulnerable component",
}

BLACK_BOX_LIMITATIONS = "Finding is based on external request/response behavior. Source code and server-side authorization logic were not reviewed."


def _classification_defaults(finding: dict[str, object]) -> dict[str, object]:
    text = " ".join(str(finding.get(key, "")) for key in ["title", "type", "reason", "evidence", "endpoint", "url"]).lower()
    if "idor" in text or "bola" in text:
        return {
            "owasp_web": "A01 Broken Access Control",
            "owasp_api": "API1 Broken Object Level Authorization",
            "manual_test_focus": ["Uji apakah object ID pada endpoint dapat diakses oleh user lain.", "Gunakan dua akun test: User A dan User B.", "Fokus pada parameter id, user_id, order_id, invoice_id, file_id."],
        }
    if "bfla" in text or "admin" in text:
        return {
            "owasp_web": "A01 Broken Access Control",
            "owasp_api": "API5 Broken Function Level Authorization",
            "manual_test_focus": ["Uji apakah user biasa dapat mengakses fungsi admin/staff.", "Fokus pada endpoint admin, manage, users, role, permission.", "Validasi status 401/403 untuk role yang tidak berwenang."],
        }
    if "business" in text or "payment" in text or "coupon" in text or "order" in text:
        return {
            "owasp_web": "A04 Insecure Design",
            "owasp_api": "API6 Unrestricted Access to Sensitive Business Flows",
            "manual_test_focus": ["Uji manipulasi parameter bisnis menggunakan akun test.", "Fokus pada price, amount, discount, coupon, status, role, payment_status.", "Pastikan perubahan penting divalidasi server-side."],
        }
    if "injection" in text or "sqli" in text or "xss" in text:
        return {
            "owasp_web": "A03 Injection",
            "owasp_api": "",
            "manual_test_focus": ["Uji input secara aman di lingkungan authorized.", "Fokus pada parameter search, query, filter, sort, id, name, email, comment.", "Cek error 500, stack trace, database error, atau perubahan perilaku response.", "Jangan gunakan payload destruktif."],
        }
    if "auth" in text or "session" in text or "cookie" in text or "csrf" in text:
        return {
            "owasp_web": "A07 Identification and Authentication Failures",
            "owasp_api": "API2 Broken Authentication",
            "manual_test_focus": ["Uji login/logout/reset password/session handling.", "Cek cookie flags, token di URL, CSRF, dan session invalidation."],
        }
    if "redirect" in text:
        return {
            "owasp_web": "A01 Broken Access Control",
            "owasp_api": "",
            "manual_test_focus": ["Uji parameter redirect, next, url, return_url secara aman.", "Secure behavior: hanya redirect ke allowlisted/internal URL."],
        }
    if "file" in text or "download" in text or "upload" in text:
        return {
            "owasp_web": "A01 Broken Access Control",
            "owasp_api": "API1 Broken Object Level Authorization",
            "manual_test_focus": ["Uji akses file antar-user dengan akun test.", "Fokus pada file_id, path, filename, document_id."],
        }
    if "sensitive" in text or "secret" in text or "token" in text:
        return {
            "owasp_web": "A02 Cryptographic Failures",
            "owasp_api": "API3 Broken Object Property Level Authorization",
            "manual_test_focus": ["Cek apakah response mengandung token, secret, debug, stack trace, data user berlebihan.", "Jangan menyimpan atau menyalin data sensitif asli."],
        }
    if "cve" in text or "component" in text or "outdated" in text or "vulnerable" in text:
        return {
            "owasp_web": "A06 Vulnerable and Outdated Components",
            "owasp_api": "API9 Improper Inventory Management",
            "manual_test_focus": ["Konfirmasi produk dan versi secara manual.", "Cek advisory vendor resmi.", "Jangan menjalankan exploit publik."],
        }
    if "misconfiguration" in text or "header" in text or "cors" in text or "debug" in text:
        return {
            "owasp_web": "A05 Security Misconfiguration",
            "owasp_api": "API8 Security Misconfiguration",
            "manual_test_focus": ["Cek header keamanan, CORS, cookie flags, debug mode, exposed server version."],
        }
    return {"owasp_web": "", "owasp_api": "", "manual_test_focus": ["Validasi temuan secara manual dengan akun dan data uji berizin."]}


def _evidence_source_for(finding: dict[str, object]) -> str:
    finding_type = str(finding.get("type", "")).lower()
    title = str(finding.get("title", "")).lower()
    if "header" in finding_type or "header" in title or "config" in finding_type:
        return "Security header"
    if "component" in finding_type or "fingerprint" in finding_type:
        return "Technology fingerprint"
    if "bola" in finding_type or "bfla" in finding_type or "business" in finding_type or "authentication" in finding_type:
        return "Endpoint behavior"
    return "HTTP response"


def _black_box_enrich(finding: dict[str, object]) -> dict[str, object]:
    enriched = dict(finding)
    endpoint = str(enriched.get("url") or enriched.get("endpoint") or "")
    from urllib.parse import urlparse

    defaults = _classification_defaults(enriched)
    enriched.setdefault("status", "Potential")
    enriched.setdefault("manual_validation_required", True)
    enriched.setdefault("testing_methodology", "black_box")
    enriched.setdefault("evidence_source", _evidence_source_for(enriched))
    enriched.setdefault("black_box_limitations", BLACK_BOX_LIMITATIONS)
    enriched.setdefault("safe_testing_note", "Manual validation only. Do not brute force, exploit, perform denial of service, upload shells, or exfiltrate data.")
    enriched.setdefault("finding_id", f"PF-{abs(hash(endpoint + str(enriched.get('type', '')))) % 100000:05d}")
    enriched.setdefault("affected_host", urlparse(endpoint).hostname or "")
    enriched.setdefault("endpoint", endpoint)
    enriched.setdefault("method", enriched.get("method", "GET"))
    enriched.setdefault("source", enriched.get("evidence_source", "HTTP response"))
    enriched.setdefault("observed_in", ["endpoint"])
    enriched.setdefault("request_summary", {"method": enriched.get("method", "GET"), "url": endpoint, "path": urlparse(endpoint).path, "query_params_masked": {}, "body_params_masked": {}, "headers_of_interest": {}})
    enriched.setdefault("response_summary", {"status_code": "", "content_type": "", "response_length": "", "interesting_headers": {}, "evidence_snippet_masked": enriched.get("evidence", "")})
    enriched.setdefault("suspicious_parameters", [])
    enriched.setdefault("reason", enriched.get("evidence", ""))
    enriched.setdefault("impact", "Dampak aktual perlu validasi manual oleh analis.")
    enriched.setdefault("owasp_web", defaults.get("owasp_web", ""))
    enriched.setdefault("owasp_api", defaults.get("owasp_api", ""))
    enriched.setdefault("manual_test_focus", defaults.get("manual_test_focus", ["Validasi temuan secara manual dengan akun dan data uji berizin."]))
    enriched.setdefault("validation_steps", enriched.get("manual_test_focus", []))
    enriched.setdefault("expected_secure_behavior", "Akses tidak sah ditolak dan input divalidasi server-side.")
    enriched.setdefault("vulnerable_behavior", "Akses atau data exposure terjadi di luar otorisasi yang dimaksud.")
    enriched.setdefault("cwe_optional", "")
    enriched.setdefault("cve_ids", enriched.get("related_cves", []))
    enriched.setdefault("cwe_ids", enriched.get("cwe", []))
    enriched.setdefault("cvss_score", enriched.get("highest_cvss", ""))
    enriched.setdefault("source_module", enriched.get("source_module", enriched.get("source", "")))
    enriched.setdefault("remediation", enriched.get("remediation", enriched.get("recommendation", "")))
    return enriched


def build_findings() -> dict[str, object]:
    headers = read_json("outputs/security_headers.json", default={}) or {}
    fingerprint = read_json("outputs/technology_fingerprint.json", default={}) or {}
    dynamic_scope = read_json("outputs/dynamic_allowed_hosts.json", default={}) or {}
    discovered = read_json("outputs/discovered_subdomains.json", default=[]) or []
    live_hosts = read_json("outputs/live_hosts.json", default=[]) or []
    external_dependencies = read_json("outputs/external_dependencies.json", default=[]) or []
    auth_endpoints = read_json("outputs/auth_endpoints.json", default=[]) or []
    endpoints = read_json("outputs/endpoints.json", default=[]) or []
    potential = read_json("outputs/potential_findings.json", default=[]) or []
    extra_sources = []
    for path in [
        "outputs/potential_auth_session_issues.json",
        "outputs/potential_security_misconfigurations.json",
        "outputs/potential_vulnerable_components.json",
        "outputs/api_top10_candidates.json",
    ]:
        data = read_json(path, default=[]) or []
        if isinstance(data, list):
            extra_sources.extend(data)
    for cve in read_json("outputs/cve_correlations.json", default=[]) or []:
        if isinstance(cve, dict):
            extra_sources.append({
                "title": "Potential Vulnerable Component",
                "type": "Vulnerable component",
                "severity": cve.get("severity", "Medium"),
                "confidence": cve.get("confidence", "Medium"),
                "endpoint": cve.get("affected_url", ""),
                "affected_host": cve.get("affected_host", ""),
                "evidence": cve.get("description", ""),
                "reason": "Potensi korelasi CVE dari teknologi/versi terdeteksi.",
                "recommendation": cve.get("remediation_guidance", ""),
                "cve_ids": [cve.get("cve_id")],
                "cvss_score": cve.get("cvss_score", ""),
                "owasp_web": "A06 Vulnerable and Outdated Components",
                "owasp_api": "API9 Improper Inventory Management",
            })
    header_findings = headers.get("findings", []) if isinstance(headers, dict) else []

    header_findings = [_black_box_enrich(finding) for finding in header_findings]
    potential = [_black_box_enrich(finding) for finding in list(potential) + extra_sources]
    all_findings = list(header_findings) + list(potential)
    summary = {
        "security_header_findings": header_findings,
        "technology_fingerprint": fingerprint,
        "dynamic_scope": dynamic_scope,
        "discovered_subdomains": discovered,
        "live_hosts": live_hosts,
        "external_dependencies": external_dependencies,
        "auth_endpoints": auth_endpoints,
        "total_endpoints": len(endpoints),
        "potential_findings": potential,
        "total_findings": len(all_findings),
        "all_findings": all_findings,
    }
    queue = [
        finding for finding in all_findings
        if finding.get("manual_validation_required") and finding.get("type") in QUEUE_TYPES
    ]
    write_json("outputs/recon_summary.json", summary)
    write_json("outputs/manual_validation_queue.json", queue)
    write_json("outputs/potential_findings.json", potential)
    write_json("outputs/alerts.json", potential)
    write_json("reports/findings.json", all_findings)
    return summary
