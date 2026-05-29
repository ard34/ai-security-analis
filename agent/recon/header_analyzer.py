from __future__ import annotations

from http.cookies import SimpleCookie
from urllib.parse import urlparse

import requests

from agent.core.models import Finding
from agent.report.json_writer import write_json

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
    "Set-Cookie",
]


def _is_api(url: str, content_type: str = "") -> bool:
    return "/api/" in urlparse(url).path.lower() or "json" in content_type.lower()


def _finding(title: str, url: str, evidence: str, api: bool) -> dict[str, object]:
    return Finding(
        title=title,
        type="Security header/config issue",
        severity="Low",
        confidence="High",
        url=url,
        evidence=evidence,
        recommendation="Validate the configuration manually and apply a least-privilege browser security policy.",
        owasp_web="A05 Security Misconfiguration",
        owasp_api="API8 Security Misconfiguration" if api else "",
        manual_validation_required=True,
    ).to_dict()


def analyze_headers(target: str, output_path: str = "outputs/security_headers.json") -> dict[str, object]:
    try:
        response = requests.head(target, allow_redirects=True, timeout=15)
        if not response.headers:
            response = requests.get(target, allow_redirects=True, timeout=15)
    except requests.RequestException:
        response = requests.get(target, allow_redirects=True, timeout=20)

    headers = {key: value for key, value in response.headers.items() if key in SECURITY_HEADERS}
    api = _is_api(response.url, response.headers.get("Content-Type", ""))
    findings: list[dict[str, object]] = []
    is_https = urlparse(response.url).scheme == "https"

    if "Content-Security-Policy" not in response.headers:
        findings.append(_finding("CSP header missing", response.url, "Content-Security-Policy not present.", api))
    if is_https and "Strict-Transport-Security" not in response.headers:
        findings.append(_finding("HSTS header missing", response.url, "Strict-Transport-Security not present on HTTPS.", api))
    if "X-Frame-Options" not in response.headers:
        findings.append(_finding("X-Frame-Options header missing", response.url, "X-Frame-Options not present.", api))
    if "X-Content-Type-Options" not in response.headers:
        findings.append(_finding("X-Content-Type-Options header missing", response.url, "X-Content-Type-Options not present.", api))
    if response.headers.get("Access-Control-Allow-Origin", "").strip() == "*":
        findings.append(_finding("CORS wildcard origin", response.url, "Access-Control-Allow-Origin is '*'.", api))

    raw_cookies = response.headers.get("Set-Cookie", "")
    if raw_cookies:
        cookie = SimpleCookie()
        cookie.load(raw_cookies)
        for name, morsel in cookie.items():
            lower = raw_cookies.lower()
            if "httponly" not in lower:
                findings.append(_finding("Cookie missing HttpOnly", response.url, f"Cookie {name} lacks HttpOnly.", api))
            if is_https and "secure" not in lower:
                findings.append(_finding("Cookie missing Secure", response.url, f"Cookie {name} lacks Secure on HTTPS.", api))
            if "samesite" not in lower:
                findings.append(_finding("Cookie missing SameSite", response.url, f"Cookie {name} lacks SameSite.", api))

    result = {
        "target": target,
        "final_url": response.url,
        "status_code": response.status_code,
        "headers": headers,
        "findings": findings,
    }
    write_json(output_path, result)
    return result
