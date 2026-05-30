from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from core.logging import audit_event_to_dict, create_audit_event
from core.policies import get_scan_policy
from core.scope import validate_scope
from modules.headers import analyze_security_headers


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _allowed_scope(allowed_domains: list[str], allowed_ips: list[str] | None) -> dict[str, list[str]]:
    return {
        "domains": list(allowed_domains or []),
        "ips": list(allowed_ips or []),
    }


def _audit_log(
    scan_id: str,
    target: str,
    scan_mode: str,
    modules_enabled: list[str],
    findings_generated: int,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "target": target,
        "scan_mode": scan_mode,
        "modules_enabled": modules_enabled,
        "commands_executed": [],
        "errors": errors or [],
        "findings_generated": findings_generated,
    }


def _scan_id() -> str:
    from uuid import uuid4

    return str(uuid4())


def _dummy_headers() -> dict[str, str]:
    return {
        "Server": "dummy",
        "Content-Type": "text/html",
    }


def run_dummy_pipeline(
    target: str,
    allowed_domains: list[str],
    allowed_ips: list[str] | None = None,
    scan_mode: str = "safe",
) -> dict[str, Any]:
    """Run a local-only dummy pipeline.

    The dummy pipeline connects policy validation, scope validation, synthetic
    assets/endpoints, and passive security-header analysis. It never performs
    network requests, never invokes external scanners, and never runs active
    testing behavior.
    """

    started_at = _utc_now()
    scan_id = _scan_id()
    allowed_scope = _allowed_scope(allowed_domains, allowed_ips)
    policy = get_scan_policy(scan_mode)
    audit_events = [
        audit_event_to_dict(
            create_audit_event(
                "scan_started",
                "Dummy scan started",
                scan_id=scan_id,
                target=target,
                status="started",
                source="pipeline",
                metadata={"scan_mode": scan_mode, "allowed_scope": allowed_scope},
            )
        )
    ]
    scope_result = validate_scope(target, allowed_domains=allowed_domains, allowed_ips=allowed_ips)

    if not scope_result.allowed or not scope_result.normalized_target:
        ended_at = _utc_now()
        reason = scope_result.reason
        audit_events.append(
            audit_event_to_dict(
                create_audit_event(
                    "scan_rejected",
                    "Dummy scan rejected by scope validation",
                    scan_id=scan_id,
                    target=target,
                    status="rejected",
                    source="pipeline",
                    metadata={"reason": reason, "scan_mode": scan_mode},
                )
            )
        )
        audit_log = _audit_log(
            scan_id=scan_id,
            target=target,
            scan_mode=scan_mode,
            modules_enabled=[],
            findings_generated=0,
            errors=[reason],
        )
        return {
            "scan_id": scan_id,
            "target": target,
            "normalized_target": scope_result.normalized_target,
            "scan_mode": scan_mode,
            "allowed_scope": allowed_scope,
            "assets": [],
            "endpoints": [],
            "findings": [],
            "audit_log": audit_log,
            "audit_events": audit_events,
            "started_at": started_at,
            "ended_at": ended_at,
            "status": "rejected",
            "reason": reason,
            "policy": policy,
        }

    normalized_target = scope_result.normalized_target
    asset = f"https://{normalized_target}"
    endpoint = "/"
    assets = [{"url": asset, "asset_type": "web", "source": "dummy_pipeline"}]
    endpoints = [{"url": f"{asset}{endpoint}", "method": "GET", "path": endpoint, "source": "dummy_pipeline"}]
    findings = analyze_security_headers(
        target=normalized_target,
        asset=asset,
        headers=_dummy_headers(),
        is_https=True,
        endpoint=endpoint,
    )
    ended_at = _utc_now()
    audit_events.append(
        audit_event_to_dict(
            create_audit_event(
                "scan_completed",
                "Dummy scan completed",
                scan_id=scan_id,
                target=normalized_target,
                status="success",
                source="pipeline",
                metadata={
                    "scan_mode": scan_mode,
                    "modules_enabled": ["security_headers"],
                    "findings_generated": len(findings),
                    "commands_executed": [],
                },
            )
        )
    )
    audit_log = _audit_log(
        scan_id=scan_id,
        target=normalized_target,
        scan_mode=scan_mode,
        modules_enabled=["security_headers"],
        findings_generated=len(findings),
    )
    return {
        "scan_id": scan_id,
        "target": target,
        "normalized_target": normalized_target,
        "scan_mode": scan_mode,
        "allowed_scope": allowed_scope,
        "assets": assets,
        "endpoints": endpoints,
        "findings": findings,
        "audit_log": audit_log,
        "audit_events": audit_events,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": "success",
        "reason": "",
        "policy": policy,
    }
