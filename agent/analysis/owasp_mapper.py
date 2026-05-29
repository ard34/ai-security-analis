from __future__ import annotations

WEB_MAPPING = {
    "idor": "A01 Broken Access Control",
    "bola": "A01 Broken Access Control",
    "bfla": "A01 Broken Access Control",
    "sensitive data exposure": "A02 Cryptographic Failures",
    "injection": "A03 Injection",
    "business logic": "A04 Insecure Design",
    "security header": "A05 Security Misconfiguration",
    "config": "A05 Security Misconfiguration",
    "vulnerable component": "A06 Vulnerable and Outdated Components",
    "authentication": "A07 Identification and Authentication Failures",
    "session": "A07 Identification and Authentication Failures",
    "integrity": "A08 Software and Data Integrity Failures",
    "logging": "A09 Security Logging and Monitoring Failures",
    "monitoring": "A09 Security Logging and Monitoring Failures",
    "ssrf": "A10 Server-Side Request Forgery",
}


def map_owasp_web(finding_type: str) -> str:
    lower = finding_type.lower()
    for needle, category in WEB_MAPPING.items():
        if needle in lower:
            return category
    return ""
