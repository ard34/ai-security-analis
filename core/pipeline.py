from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from core.models import Asset, Endpoint, ScanSession, Target, ToolResult
from core.policies import get_scan_policy
from core.scope import validate_scope
from modules.headers import analyze_security_headers


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _base_url_for_target(normalized_target: str) -> str:
    parsed = urlparse(normalized_target)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{normalized_target}"


def _fake_headers() -> dict[str, str]:
    return {
        "Server": "dummy-local-test-server",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cross-Origin-Opener-Policy": "same-origin",
    }


def run_dummy_pipeline(
    target_input: str,
    allowed_domains: list[str],
    scan_mode: str = "strict",
    allowed_ips: list[str] | None = None,
    denied_patterns: list[str] | None = None,
) -> ScanSession:
    """Run a local-only dummy scan for foundation testing.

    No network clients or external tools are used here. All assets, endpoints,
    and headers are synthetic so guardrails and data models can be tested first.
    """

    started_at = _utc_now()
    scope_result = validate_scope(
        target_input,
        allowed_domains=allowed_domains,
        allowed_ips=allowed_ips,
        denied_patterns=denied_patterns,
    )
    if not scope_result.allowed or not scope_result.normalized_target:
        raise ValueError(f"Target rejected by scope validation: {scope_result.reason}")

    policy = get_scan_policy(scan_mode)
    target = Target(
        raw_input=target_input,
        normalized_target=scope_result.normalized_target,
        allowed_domains=allowed_domains,
        allowed_ips=allowed_ips or [],
    )
    session = ScanSession(target=target, scan_mode=scan_mode)
    session.started_at = started_at

    base_url = _base_url_for_target(scope_result.normalized_target)
    fake_asset = Asset(value=base_url, asset_type="web_host", source="dummy_pipeline")
    fake_endpoint = Endpoint(url=f"{base_url}/login", method="GET", path="/login", source="dummy_pipeline")
    dummy_headers = _fake_headers()

    findings = analyze_security_headers(
        target=scope_result.normalized_target,
        asset=fake_asset.value,
        headers=dummy_headers,
        is_https=True,
        endpoint=fake_endpoint.path,
    )
    session.assets.append(fake_asset)
    session.endpoints.append(fake_endpoint)
    session.findings.extend(findings)
    session.tool_results.append(
        ToolResult(
            tool_name="dummy_security_headers",
            status="Done",
            result_count=len(findings),
            commands_executed=[],
            errors=[],
        )
    )
    session.finish()

    session.audit_log = {
        "scan_id": session.scan_id,
        "target": scope_result.normalized_target,
        "authorized_scope": {
            "allowed_domains": allowed_domains,
            "allowed_ips": allowed_ips or [],
            "denied_patterns": denied_patterns or [],
        },
        "scan_mode": scan_mode,
        "policy": policy,
        "modules_enabled": ["dummy_asset_generation", "security_headers"],
        "start_time": session.started_at,
        "end_time": session.ended_at,
        "commands_executed": [],
        "errors": [],
        "findings_generated": len(session.findings),
        "scope_validation": {
            "allowed": scope_result.allowed,
            "normalized_target": scope_result.normalized_target,
            "reason": scope_result.reason,
        },
    }
    return session
