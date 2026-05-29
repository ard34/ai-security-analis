from __future__ import annotations

from datetime import datetime, timezone

from core.models import Asset, Endpoint, ScanSession, Target, ToolResult
from core.policies import get_scan_policy
from core.scope import validate_scope
from modules.headers import analyze_security_headers


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _allowed_scope(allowed_domains: list[str], allowed_ips: list[str] | None) -> dict[str, list[str]]:
    return {
        "allowed_domains": list(allowed_domains or []),
        "allowed_ips": list(allowed_ips or []),
    }


def _audit_log(
    session: ScanSession,
    target: str,
    scan_mode: str,
    modules_enabled: list[str],
    errors: list[str] | None = None,
) -> dict[str, object]:
    return {
        "scan_id": session.scan_id,
        "target": target,
        "scan_mode": scan_mode,
        "modules_enabled": modules_enabled,
        "commands_executed": [],
        "errors": errors or [],
        "findings_generated": len(session.findings),
    }


def _dummy_headers() -> dict[str, str]:
    return {
        "Server": "dummy-local-test-server",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }


def _new_session(
    raw_target: str,
    normalized_target: str,
    allowed_domains: list[str],
    allowed_ips: list[str] | None,
    scan_mode: str,
    status: str,
) -> ScanSession:
    session = ScanSession(
        target=Target(
            raw_input=raw_target,
            normalized_target=normalized_target,
            allowed_domains=list(allowed_domains or []),
            allowed_ips=list(allowed_ips or []),
        ),
        scan_mode=scan_mode,
        status=status,
        allowed_scope=_allowed_scope(allowed_domains, allowed_ips),
    )
    return session


def run_dummy_pipeline(
    target: str,
    allowed_domains: list[str],
    allowed_ips: list[str] | None = None,
    scan_mode: str = "safe",
) -> ScanSession:
    """Run a local-only dummy pipeline.

    This function validates policy and scope, generates synthetic assets,
    analyzes synthetic headers, and records audit metadata. It never performs
    network requests and never invokes external scanners or active testing.
    """

    policy = get_scan_policy(scan_mode)
    scope_result = validate_scope(target, allowed_domains=allowed_domains, allowed_ips=allowed_ips)
    normalized_target = scope_result.normalized_target or ""

    if not scope_result.allowed or not normalized_target:
        session = _new_session(target, normalized_target, allowed_domains, allowed_ips, scan_mode, "rejected")
        session.finish()
        session.audit_log = _audit_log(
            session=session,
            target=target,
            scan_mode=scan_mode,
            modules_enabled=[],
            errors=[scope_result.reason],
        )
        session.audit_log["allowed_scope"] = session.allowed_scope
        session.audit_log["scope_validation"] = {
            "allowed": scope_result.allowed,
            "normalized_target": scope_result.normalized_target,
            "reason": scope_result.reason,
        }
        session.audit_log["policy"] = policy
        return session

    session = _new_session(target, normalized_target, allowed_domains, allowed_ips, scan_mode, "success")
    asset_url = f"https://{normalized_target}"
    endpoint_path = "/"
    session.assets.append(Asset(value=asset_url, asset_type="web", source="dummy_pipeline"))
    session.endpoints.append(Endpoint(url=asset_url + endpoint_path, method="GET", path=endpoint_path, source="dummy_pipeline"))

    findings = analyze_security_headers(
        target=normalized_target,
        asset=asset_url,
        headers=_dummy_headers(),
        is_https=True,
        endpoint=endpoint_path,
    )
    session.findings.extend(findings)
    session.tool_results.append(
        ToolResult(
            tool_name="security_headers",
            status="Done",
            result_count=len(findings),
            commands_executed=[],
            errors=[],
        )
    )
    session.finish()
    session.audit_log = _audit_log(
        session=session,
        target=normalized_target,
        scan_mode=scan_mode,
        modules_enabled=["security_headers"],
    )
    session.audit_log["allowed_scope"] = session.allowed_scope
    session.audit_log["scope_validation"] = {
        "allowed": scope_result.allowed,
        "normalized_target": scope_result.normalized_target,
        "reason": scope_result.reason,
    }
    session.audit_log["policy"] = policy
    return session
