from __future__ import annotations

from typing import Any

from core.http_client import SafeHTTPRequest, perform_safe_http_request
from core.modules import BaseReconModule, ModuleContext, ModuleResult
from modules.headers import analyze_security_headers


SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization"}


class LiveSecurityHeadersModule(BaseReconModule):
    name = "live_security_headers"
    description = "Fetches authorized HTTP headers through SafeHTTPClient and analyzes security headers."
    required_policy_flags = ("allow_network",)

    def run(self, context: ModuleContext) -> ModuleResult:
        allow_network = bool(context.policy.get("allow_network", False))
        if not allow_network:
            return ModuleResult(module_name=self.name, status="skipped", errors=["Network access is disabled by policy."])

        url = str(context.metadata.get("url") or f"https://{context.normalized_target}")
        method = str(context.metadata.get("method") or "HEAD")
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
        evidence = [_response_evidence(response)]
        if response.error:
            return ModuleResult(
                module_name=self.name,
                status="failed",
                evidence=evidence,
                errors=[response.error],
                metadata={"audit_event_count": len(response.audit_events)},
            )

        findings = [
            finding.to_dict()
            for finding in analyze_security_headers(
                target=context.normalized_target,
                asset=response.final_url or url,
                headers=response.headers,
                is_https=(response.final_url or url).lower().startswith("https://"),
                endpoint="/",
            )
        ]
        return ModuleResult(
            module_name=self.name,
            status="success",
            findings=findings,
            evidence=evidence,
            metadata={"status_code": response.status_code, "audit_events": response.audit_events},
        )


def _response_evidence(response: Any) -> dict[str, Any]:
    safe_header_names = sorted(
        str(name)
        for name in (response.headers or {})
        if str(name).strip().lower() not in SENSITIVE_HEADER_NAMES
    )
    return {
        "type": "http_headers",
        "status_code": response.status_code,
        "header_names": safe_header_names,
        "final_url": response.final_url,
        "audit_events": response.audit_events,
    }
