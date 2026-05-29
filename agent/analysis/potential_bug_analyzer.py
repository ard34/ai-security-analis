from __future__ import annotations

import re
from urllib.parse import urlparse

from agent.analysis.api_top10_mapper import map_owasp_api
from agent.analysis.owasp_mapper import map_owasp_web
from agent.analysis.risk_scorer import score_risk
from agent.core.models import Finding
from agent.core.scope_validator import is_allowed_url, load_dynamic_allowed_hosts
from agent.report.json_writer import read_json, write_json

ID_KEYS = {"id", "user_id", "order_id", "invoice_id", "account_id"}
BUSINESS_KEYS = {"price", "quantity", "discount", "coupon", "role", "is_admin", "status", "payment_status", "order_status"}
INJECTION_KEYS = {"q", "search", "query", "filter", "sort", "redirect", "url", "callback", "next", "file", "path", "id", "name", "email", "comment", "message"}
REDIRECT_KEYS = {"redirect", "url", "callback", "next", "return", "returnurl", "continue"}
FILE_KEYS = {"file", "path", "download", "export", "document", "attachment"}


def _classification_map(path: str) -> dict[str, str]:
    items = read_json(path, default=[]) or []
    return {str(item.get("url")): str(item.get("classification", "unknown")) for item in items}


BLACK_BOX_LIMITATIONS = "Finding is based on external request/response behavior. Source code and server-side authorization logic were not reviewed."
SAFE_TESTING_NOTE = "Manual validation only. Use authorized test accounts and benign inputs. Do not brute force, exploit, exfiltrate data, upload shells, or perform denial-of-service testing."


def _focus(ftype: str) -> list[str]:
    mapping = {
        "BOLA/IDOR": ["Uji apakah object ID pada endpoint dapat diakses oleh user lain.", "Gunakan dua akun test: User A dan User B.", "Fokus pada parameter id, user_id, order_id, invoice_id, file_id."],
        "BFLA": ["Uji apakah user biasa dapat mengakses fungsi admin/staff.", "Fokus pada endpoint admin, manage, users, role, permission.", "Validasi status 401/403 untuk role yang tidak berwenang."],
        "Business logic flaw": ["Uji manipulasi parameter bisnis menggunakan akun test.", "Fokus pada price, amount, discount, coupon, status, role, payment_status.", "Pastikan perubahan penting divalidasi server-side."],
        "Injection indicator": ["Uji input secara aman di lingkungan authorized.", "Fokus pada parameter search, query, filter, sort, id, name, email, comment.", "Cek error 500, stack trace, database error, atau perubahan perilaku response.", "Jangan gunakan payload destruktif."],
        "Authentication/session weakness": ["Uji login/logout/reset password/session handling.", "Cek cookie flags, token di URL, CSRF, dan session invalidation."],
        "Open redirect": ["Uji parameter redirect, next, url, return_url secara aman.", "Secure behavior: hanya redirect ke allowlisted/internal URL."],
        "File access risk": ["Uji akses file antar-user dengan akun test.", "Fokus pada file_id, path, filename, document_id."],
        "Sensitive data exposure": ["Cek apakah response mengandung token, secret, debug, stack trace, data user berlebihan.", "Jangan menyimpan atau menyalin data sensitif asli."],
        "Security misconfiguration": ["Cek header keamanan, CORS, cookie flags, debug mode, exposed server version."],
        "Vulnerable component": ["Konfirmasi nama dan versi komponen secara manual.", "Cek advisory resmi sebelum membuat tiket vulnerability."],
    }
    return mapping.get(ftype, ["Validasi temuan secara manual dengan data dan akun uji berizin."])


def _headers_of_interest(headers: dict[str, object]) -> dict[str, object]:
    wanted = {"authorization", "cookie", "content-type", "origin", "referer", "x-csrf-token"}
    return {key: value for key, value in headers.items() if str(key).lower() in wanted}


def _evidence_details(entry: dict[str, object], ftype: str, evidence: str, evidence_source: str, classification: str) -> dict[str, object]:
    from urllib.parse import urlparse

    url = str(entry.get("url", ""))
    parsed = urlparse(url)
    request_headers = entry.get("request_headers") if isinstance(entry.get("request_headers"), dict) else {}
    response_headers = entry.get("response_headers") if isinstance(entry.get("response_headers"), dict) else {}
    query_params = entry.get("query_params") if isinstance(entry.get("query_params"), dict) else {}
    body_params = entry.get("body_params") if isinstance(entry.get("body_params"), dict) else {}
    suspicious = sorted(set(query_params) & (ID_KEYS | BUSINESS_KEYS | INJECTION_KEYS | REDIRECT_KEYS | FILE_KEYS))
    response_body = str(entry.get("response_body_sample", ""))
    observed = ["endpoint"]
    if suspicious:
        observed.append("parameter")
    if response_headers:
        observed.append("header")
    if response_body:
        observed.append("response")
    return {
        "finding_id": f"PF-{abs(hash((ftype, url, evidence))) % 100000:05d}",
        "affected_host": parsed.hostname or "",
        "endpoint": url,
        "method": str(entry.get("method", "GET")),
        "source": evidence_source,
        "observed_in": observed,
        "request_summary": {
            "method": str(entry.get("method", "GET")),
            "url": url,
            "path": parsed.path,
            "query_params_masked": query_params,
            "body_params_masked": body_params,
            "headers_of_interest": _headers_of_interest(request_headers),
        },
        "response_summary": {
            "status_code": entry.get("status_code", ""),
            "content_type": entry.get("content_type", ""),
            "response_length": len(response_body),
            "interesting_headers": _headers_of_interest(response_headers),
            "evidence_snippet_masked": response_body[:500],
        },
        "suspicious_parameters": suspicious,
        "reason": evidence,
        "impact": f"Potensi risiko pada area {classification}; dampak aktual perlu validasi manual.",
        "manual_test_focus": _focus(ftype),
        "validation_steps": _focus(ftype),
        "expected_secure_behavior": "Akses tidak sah ditolak, input divalidasi server-side, dan data sensitif tidak terekspos.",
        "vulnerable_behavior": "Akses, perubahan state, redirect, atau data exposure terjadi di luar otorisasi yang dimaksud.",
    }


def _add(
    findings: list[dict[str, object]],
    title: str,
    ftype: str,
    entry: dict[str, object],
    classification: str,
    evidence: str,
    recommendation: str,
    sensitive: bool = False,
    evidence_source: str = "Burp HAR",
) -> None:
    severity, confidence = score_risk(entry, classification, sensitive)
    finding = Finding(
            title=title,
            type=ftype,
            severity=severity,
            confidence=confidence,
            url=str(entry.get("url", "")),
            evidence=evidence,
            recommendation=recommendation,
            owasp_web=map_owasp_web(ftype),
            owasp_api=map_owasp_api(ftype),
            manual_validation_required=True,
            status="Potential",
            testing_methodology="black_box",
            evidence_source=evidence_source,
            black_box_limitations=BLACK_BOX_LIMITATIONS,
            safe_testing_note=SAFE_TESTING_NOTE,
        ).to_dict()
    finding.update(_evidence_details(entry, ftype, evidence, evidence_source, classification))
    findings.append(finding)


def analyze_potential_bugs(
    history_path: str = "outputs/http_history.json",
    classification_path: str = "outputs/endpoint_classification.json",
    evidence_source: str = "Burp HAR",
) -> list[dict[str, object]]:
    history = read_json(history_path, default=[]) or []
    classifications = _classification_map(classification_path)
    dynamic_allowed_hosts = load_dynamic_allowed_hosts()
    findings: list[dict[str, object]] = []

    for entry in history:
        url = str(entry.get("url", ""))
        if dynamic_allowed_hosts and not is_allowed_url(url, dynamic_allowed_hosts):
            continue
        path = urlparse(url).path.lower()
        params = entry.get("query_params") if isinstance(entry.get("query_params"), dict) else {}
        param_keys = {str(key).lower() for key in params.keys()}
        classification = classifications.get(url, "unknown")
        status = int(entry.get("status_code") or 0)
        response_body = str(entry.get("response_body_sample", "")).lower()
        request_headers = entry.get("request_headers") if isinstance(entry.get("request_headers"), dict) else {}
        authenticated = any(key.lower() in {"authorization", "cookie"} for key in request_headers)
        has_object_id = bool(param_keys & ID_KEYS or re.search(r"/(\d{2,}|[0-9a-f]{8}-[0-9a-f-]{27,})", path))

        if has_object_id and authenticated and status == 200 and classification in {"order", "invoice", "profile", "account", "api"}:
            _add(findings, "Potential IDOR/BOLA", "BOLA/IDOR", entry, classification, "Object identifier observed in authenticated 200 response.", "Manually compare access using two authorized test users without modifying data.", evidence_source=evidence_source)
        if classification == "admin-like" and authenticated and status not in {401, 403}:
            _add(findings, "Potential BFLA", "BFLA", entry, classification, "Admin-like endpoint reachable in authenticated traffic.", "Verify expected role requirements using a low-privilege authorized account.", evidence_source=evidence_source)
        if param_keys & BUSINESS_KEYS:
            _add(findings, "Potential Business Logic Flaw", "Business logic flaw", entry, classification, f"Business-sensitive parameters present: {sorted(param_keys & BUSINESS_KEYS)}.", "Review server-side validation and attempt only safe manual value changes in a lab or authorized staging flow.", evidence_source=evidence_source)
        if any(term in path for term in ["logout", "login", "reset-password"]) or any(key in url.lower() for key in ["token=", "access_token="]) or "csrf" in response_body:
            _add(findings, "Potential Authentication Weakness", "Authentication/session weakness", entry, classification, "Auth/session pattern requires manual review.", "Inspect session handling, token placement, and CSRF behavior manually through Burp.", evidence_source=evidence_source)
        if param_keys & INJECTION_KEYS:
            _add(findings, "Potential Injection Point", "Injection indicator", entry, classification, f"Input-like parameters present: {sorted(param_keys & INJECTION_KEYS)}.", "Analyze framework/CDN/WAF context first. Do not send aggressive payloads; use benign validation in an authorized lab.", evidence_source=evidence_source)
        if param_keys & REDIRECT_KEYS:
            _add(findings, "Potential Open Redirect", "Open redirect", entry, classification, f"Redirect-like parameters present: {sorted(param_keys & REDIRECT_KEYS)}.", "Validate with same-origin and clearly benign external URL checks only where authorized; do not chain into phishing or token theft scenarios.", evidence_source=evidence_source)
        if param_keys & FILE_KEYS or any(term in path for term in ["/download", "/export", "/file", "/files"]):
            _add(findings, "Potential File Access Risk", "File access risk", entry, classification, "File path, download, or export pattern observed.", "Confirm authorization and path handling using only safe test files created for the assessment.", evidence_source=evidence_source)
        sensitive_markers = ["[redacted]", "stack trace", "traceback", "internal_id", "debug", "password_hash", "role"]
        if any(marker in response_body for marker in sensitive_markers):
            _add(findings, "Potential Sensitive Data Exposure", "Sensitive data exposure", entry, classification, "Response sample contains sensitive-data or debug indicators after masking.", "Review whether the response exposes unnecessary fields to this user role.", sensitive=True, evidence_source=evidence_source)
        response_headers = entry.get("response_headers", {}) if isinstance(entry.get("response_headers"), dict) else {}
        if status in {500, 502, 503} or "x-powered-by" in {str(key).lower() for key in response_headers.keys()}:
            _add(findings, "Potential Security Misconfiguration", "Security misconfiguration", entry, classification, "Error response or exposed implementation header observed.", "Review error handling and exposed headers manually; do not attempt exploit automation.", evidence_source=evidence_source)

    fingerprint = read_json("outputs/technology_fingerprint.json", default={}) or {}
    for item in fingerprint.get("hosts", []) if isinstance(fingerprint, dict) else []:
        if not isinstance(item, dict):
            continue
        detected = item.get("detected", [])
        if detected or item.get("whatweb"):
            _add(
                findings,
                "Potential Vulnerable Component",
                "Vulnerable component",
                {"url": str(item.get("final_url") or item.get("target") or ""), "method": "GET", "status_code": 0, "request_headers": {}},
                "unknown",
                "Technology fingerprint observed. Version and CVE exposure require manual validation.",
                "Manually confirm component names and versions from authorized evidence before creating vulnerability tickets.",
                evidence_source="Technology fingerprint",
            )

    if evidence_source == "Authenticated Browser Crawl":
        auth_summary = read_json("outputs/authenticated_crawl_summary.json", default={}) or {}
        risky_actions = auth_summary.get("risky_actions_skipped", []) if isinstance(auth_summary, dict) else []
        seen_risky = set()
        for item in risky_actions if isinstance(risky_actions, list) else []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", ""))
            if not url or url in seen_risky:
                continue
            seen_risky.add(url)
            _add(
                findings,
                "Potential Risky Authenticated Action",
                "Business logic flaw",
                {"url": url, "method": "UNKNOWN", "status_code": 0, "request_headers": {}},
                "unknown",
                f"Authenticated crawler skipped risky action for manual validation: {item.get('reason', 'risky_action')}.",
                "Review the action manually in Burp with an authorized account. Do not submit destructive or payment-changing actions unless explicitly approved in a controlled environment.",
                evidence_source=evidence_source,
            )

    write_json("outputs/potential_findings.json", findings)
    return findings
