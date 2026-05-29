from __future__ import annotations

API_MAPPING = {
    "bola": "API1 Broken Object Level Authorization",
    "broken auth": "API2 Broken Authentication",
    "authentication": "API2 Broken Authentication",
    "excessive data": "API3 Broken Object Property Level Authorization",
    "missing rate limit": "API4 Unrestricted Resource Consumption",
    "bfla": "API5 Broken Function Level Authorization",
    "business flow": "API6 Unrestricted Access to Sensitive Business Flows",
    "ssrf": "API7 Server Side Request Forgery",
    "misconfiguration": "API8 Security Misconfiguration",
    "cors": "API8 Security Misconfiguration",
    "deprecated": "API9 Improper Inventory Management",
    "third-party": "API10 Unsafe Consumption of APIs",
}


def map_owasp_api(finding_type: str) -> str:
    lower = finding_type.lower()
    for needle, category in API_MAPPING.items():
        if needle in lower:
            return category
    return ""
