from __future__ import annotations

from typing import Any

from core.http_client import SafeHTTPRequest, perform_safe_http_request
from core.modules import BaseReconModule, ModuleContext, ModuleResult


SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization"}


class HTTPFingerprintModule(BaseReconModule):
    name = "http_fingerprint"
    description = "Performs lightweight HTTP fingerprinting from authorized response headers."
    required_policy_flags = ("allow_network",)

    def run(self, context: ModuleContext) -> ModuleResult:
        allow_network = bool(context.policy.get("allow_network", False))
        if not allow_network:
            return ModuleResult(module_name=self.name, status="skipped", errors=["Network access is disabled by policy."])

        url = str(context.metadata.get("url") or f"https://{context.normalized_target}")
        method = "HEAD"
        opener = context.metadata.get("http_opener")
        response = perform_safe_http_request(
            SafeHTTPRequest(
                method=method,
                url=url,
                allowed_domains=context.allowed_domains,
                allowed_ips=context.allowed_ips,
                scan_id=context.scan_id,
                scan_mode=context.scan_mode,
            ),
            allow_network=allow_network,
            opener=opener,
        )
        if response.error and context.metadata.get("allow_get_fallback"):
            response = perform_safe_http_request(
                SafeHTTPRequest(
                    method="GET",
                    url=url,
                    allowed_domains=context.allowed_domains,
                    allowed_ips=context.allowed_ips,
                    scan_id=context.scan_id,
                    scan_mode=context.scan_mode,
                    max_body_bytes=0,
                ),
                allow_network=allow_network,
                opener=opener,
            )
        fingerprint = sanitize_fingerprint_headers(response.headers or {})
        evidence = [{"type": "http_fingerprint", "fingerprint": fingerprint, "status_code": response.status_code, "final_url": response.final_url}]
        if response.error:
            return ModuleResult(module_name=self.name, status="failed", evidence=evidence, errors=[response.error])

        findings: list[dict[str, Any]] = []
        if fingerprint.get("server"):
            findings.append(_finding(context, "Server banner exposed", "info", "low", "Server header is present."))
        if fingerprint.get("x_powered_by"):
            findings.append(_finding(context, "X-Powered-By header exposed", "info", "low", "X-Powered-By header is present."))
        return ModuleResult(module_name=self.name, status="success", findings=findings, evidence=evidence, metadata={"audit_events": response.audit_events})


def sanitize_fingerprint_headers(headers: dict[str, str]) -> dict[str, Any]:
    normalized = {str(key).strip().lower(): str(value) for key, value in dict(headers or {}).items()}
    result: dict[str, Any] = {}
    if "server" in normalized:
        result["server"] = normalized["server"]
    if "x-powered-by" in normalized:
        result["x_powered_by"] = normalized["x-powered-by"]
    if "content-type" in normalized:
        result["content_type"] = normalized["content-type"]
    if "via" in normalized:
        result["via"] = normalized["via"]
    if "cf-ray" in normalized:
        result["cf_ray_present"] = True
    if "x-cache" in normalized:
        result["x_cache"] = normalized["x-cache"]
    result["strict_transport_security_present"] = "strict-transport-security" in normalized
    result["content_security_policy_present"] = "content-security-policy" in normalized
    result["set_cookie_present"] = "set-cookie" in normalized
    for sensitive in SENSITIVE_HEADER_NAMES:
        result.pop(sensitive, None)
    return result


def _finding(context: ModuleContext, title: str, severity: str, confidence: str, evidence: str) -> dict[str, Any]:
    return {
        "target": context.normalized_target,
        "asset": f"https://{context.normalized_target}",
        "endpoint": "/",
        "module": HTTPFingerprintModule.name,
        "finding_type": "http_fingerprint",
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "recommendation": "Review whether exposed headers reveal unnecessary implementation details.",
        "source": "http_fingerprint",
        "is_potential": True,
    }
