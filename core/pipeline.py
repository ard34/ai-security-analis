from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from core.execution import (
    SafeExecutionContext,
    create_execution_decision,
    execution_decision_to_dict,
    safe_execution_context_to_dict,
)
from core.logging import audit_event_to_dict, create_audit_event
from core.models import Finding
from core.modules import ModuleContext, merge_module_results, module_result_to_dict, run_module_safely
from core.policies import get_scan_policy
from core.scope import validate_scope
from modules.dummy_module import DummyPassiveModule
from modules.headers import SecurityHeadersModule


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


def _finding_from_dict(payload: dict[str, Any], target: str, asset: str, endpoint: str) -> Finding:
    return Finding(
        target=str(payload.get("target") or target),
        asset=str(payload.get("asset") or asset),
        endpoint=str(payload.get("endpoint") or endpoint),
        module=str(payload.get("module") or ""),
        finding_type=str(payload.get("finding_type") or "informational"),
        title=str(payload.get("title") or ""),
        severity=str(payload.get("severity") or "info"),
        confidence=str(payload.get("confidence") or "low"),
        evidence=str(payload.get("evidence") or ""),
        recommendation=str(payload.get("recommendation") or ""),
        source=str(payload.get("source") or "module_interface"),
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
    )


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
    execution_context = SafeExecutionContext(
        scan_id=scan_id,
        target=target,
        allowed_domains=allowed_domains,
        allowed_ips=allowed_ips or [],
        scan_mode=scan_mode,
        metadata={"pipeline": "dummy_pipeline"},
    )
    execution_decisions = [
        create_execution_decision(
            "local:dummy_pipeline",
            target,
            execution_context,
            metadata={"stage": "pipeline_start"},
        )
    ]
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
            "execution_context": safe_execution_context_to_dict(execution_context),
            "execution_decisions": [execution_decision_to_dict(decision) for decision in execution_decisions],
            "started_at": started_at,
            "ended_at": ended_at,
            "status": "rejected",
            "reason": reason,
            "policy": policy,
        }

    normalized_target = scope_result.normalized_target
    asset = f"https://{normalized_target}"
    endpoint = "/"
    module_context = ModuleContext(
        scan_id=scan_id,
        target=target,
        normalized_target=normalized_target,
        allowed_domains=allowed_domains,
        allowed_ips=allowed_ips or [],
        scan_mode=scan_mode,
        policy=policy,
        metadata={"headers": _dummy_headers(), "is_https": True, "asset": asset, "endpoint": endpoint},
    )
    execution_decisions.append(
        create_execution_decision(
            "local:security_headers",
            normalized_target,
            execution_context,
            metadata={"module": "security_headers"},
        )
    )
    module_results = [
        run_module_safely(DummyPassiveModule(), module_context),
        run_module_safely(SecurityHeadersModule(), module_context),
    ]
    merged_modules = merge_module_results(module_results)
    assets = [{"url": asset, "asset_type": "web", "source": "dummy_pipeline"}]
    endpoints = [{"url": f"{asset}{endpoint}", "method": "GET", "path": endpoint, "source": "dummy_pipeline"}]
    findings = [
        _finding_from_dict(finding, normalized_target, asset, endpoint)
        for finding in merged_modules["findings"]
        if finding.get("module") == "security_headers"
    ]
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
                    "modules_enabled": merged_modules["modules"],
                    "findings_generated": len(findings),
                    "commands_executed": merged_modules["commands_executed"],
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
        errors=merged_modules["errors"],
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
        "execution_context": safe_execution_context_to_dict(execution_context),
        "execution_decisions": [execution_decision_to_dict(decision) for decision in execution_decisions],
        "module_results": [module_result_to_dict(result) for result in module_results],
        "module_summary": merged_modules,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": "success",
        "reason": "",
        "policy": policy,
    }
