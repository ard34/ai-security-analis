from __future__ import annotations

from http.cookies import SimpleCookie

import requests

from agent.report.json_writer import write_json

HEADER_KEYS = [
    "Server",
    "X-Powered-By",
    "Set-Cookie",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
]


def review_security_headers(live_hosts: list[dict[str, object]], output_path: str = "outputs/recon/security_headers.json") -> list[dict[str, object]]:
    results = []
    for host in live_hosts:
        url = str(host.get("url", ""))
        if not url:
            continue
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
        except requests.RequestException as exc:
            results.append({"host": host.get("hostname", ""), "url": url, "status": "failed", "reason": str(exc)})
            continue
        headers = {key: response.headers.get(key, "") for key in HEADER_KEYS if response.headers.get(key)}
        cookie_issues = []
        raw_cookie = response.headers.get("Set-Cookie", "")
        if raw_cookie:
            cookie = SimpleCookie()
            cookie.load(raw_cookie)
            lower = raw_cookie.lower()
            for name in cookie:
                if "httponly" not in lower:
                    cookie_issues.append(f"{name} missing HttpOnly")
                if response.url.startswith("https://") and "secure" not in lower:
                    cookie_issues.append(f"{name} missing Secure")
                if "samesite" not in lower:
                    cookie_issues.append(f"{name} missing SameSite")
        cors = response.headers.get("Access-Control-Allow-Origin", "")
        missing = {
            "missing_csp": "Content-Security-Policy" not in response.headers,
            "missing_hsts": response.url.startswith("https://") and "Strict-Transport-Security" not in response.headers,
            "missing_x_frame_options": "X-Frame-Options" not in response.headers,
            "missing_x_content_type_options": "X-Content-Type-Options" not in response.headers,
        }
        results.append(
            {
                "host": host.get("hostname", ""),
                "url": response.url,
                "status": "collected",
                "headers": headers,
                **missing,
                "cookie_issues": cookie_issues,
                "cors_notes": "Wildcard origin" if cors.strip() == "*" else ("CORS present" if cors else ""),
                "issue_count": sum(1 for value in missing.values() if value) + len(cookie_issues) + (1 if cors.strip() == "*" else 0),
            }
        )
    write_json(output_path, results)
    write_json("outputs/security_headers.json", {"hosts": results, "findings": []})
    return results
