from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from core.assessment import AssessmentProject, is_assessment_approved
from core.evidence import collect_evidence_from_scan_result, evidence_item_to_dict
from core.execution import (
    ExecutionPolicy,
    ExecutionState,
    KillSwitch,
    RateLimitConfig,
    SafeExecutionContext,
    ScanBudget,
    TimeoutConfig,
    create_execution_decision,
    execution_decision_to_dict,
    safe_execution_context_to_dict,
    validate_execution_policy,
    validate_rate_limit_config,
    validate_scan_budget,
    validate_timeout_config,
)
from core.finding_dedup import deduplicate_findings, deduped_findings_to_dicts
from core.logging import audit_event_to_dict, create_audit_event, redact_sensitive_data
from core.manual_testing import generate_manual_testing_recommendations, manual_test_recommendation_to_dict
from core.modules import ModuleContext, ModuleResult, merge_module_results, module_result_to_dict, run_module_safely
from core.scope import validate_scope
from modules.http_fingerprint import HTTPFingerprintModule
from modules.live_dns import LiveDNSModule
from modules.live_headers import LiveSecurityHeadersModule
from modules.robots_sitemap import RobotsSitemapModule


SAFE_LIVE_MODULE_ALLOWLIST = {
    "live_dns",
    "live_security_headers",
    "http_fingerprint",
    "robots_sitemap",
}


@dataclass(frozen=True)
class LivePipelineConfig:
    safe_live: bool = False
    allow_network: bool = False
    enabled_modules: tuple[str, ...] = (
        "live_dns",
        "live_security_headers",
        "http_fingerprint",
        "robots_sitemap",
    )
    scan_budget: ScanBudget = field(default_factory=ScanBudget)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    timeout: TimeoutConfig = field(default_factory=TimeoutConfig)
    kill_switch: KillSwitch = field(default_factory=KillSwitch)
    max_findings: int = 200


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def generate_scan_id(prefix: str = "live") -> str:
    safe_prefix = str(redact_sensitive_data(prefix or "live")).strip().lower() or "live"
    safe_prefix = "".join(character for character in safe_prefix if character.isalnum() or character == "_") or "live"
    return f"{safe_prefix}_{uuid4().hex[:12]}"


def build_live_execution_policy(config: LivePipelineConfig) -> ExecutionPolicy:
    return ExecutionPolicy(
        allow_network=bool(config.allow_network),
        allow_external_tools=False,
        allow_exploit=False,
        allow_bruteforce=False,
        allow_dos=False,
        allow_zap_active=False,
        require_scope_validation=True,
        require_approval=True,
        allowed_methods=("GET", "HEAD"),
    )


def validate_live_pipeline_config(config: LivePipelineConfig) -> None:
    if not isinstance(config, LivePipelineConfig):
        raise ValueError("config must be a LivePipelineConfig.")
    unknown = [name for name in config.enabled_modules if name not in SAFE_LIVE_MODULE_ALLOWLIST]
    if unknown:
        raise ValueError(f"Safe-live module is not allowlisted: {unknown[0]}")
    if int(config.max_findings) < 1 or int(config.max_findings) > 1000:
        raise ValueError("max_findings must be between 1 and 1000.")
    validate_scan_budget(config.scan_budget)
    validate_rate_limit_config(config.rate_limit)
    validate_timeout_config(config.timeout)
    validate_execution_policy(build_live_execution_policy(config))


def _default_project_target(project: AssessmentProject) -> str:
    if project.scope.allowed_domains:
        return project.scope.allowed_domains[0]
    if project.scope.allowed_ips:
        return project.scope.allowed_ips[0]
    raise ValueError("Assessment project does not define an allowed target.")


def _target_from_metadata(project: AssessmentProject, metadata: dict[str, Any] | None) -> str:
    payload = metadata if isinstance(metadata, dict) else {}
    return str(payload.get("target") or _default_project_target(project)).strip()


def _validate_target_in_scope(project: AssessmentProject, target: str) -> tuple[str, str]:
    scope = validate_scope(
        target,
        allowed_domains=project.scope.allowed_domains,
        allowed_ips=project.scope.allowed_ips,
        denied_patterns=project.scope.denied_patterns,
    )
    if not scope.allowed or not scope.normalized_target:
        raise ValueError(scope.reason)
    return scope.normalized_target, scope.reason


def _policy_to_dict(policy: ExecutionPolicy) -> dict[str, Any]:
    return {
        "allow_network": policy.allow_network,
        "allow_external_tools": policy.allow_external_tools,
        "allow_exploit": policy.allow_exploit,
        "allow_bruteforce": policy.allow_bruteforce,
        "allow_dos": policy.allow_dos,
        "allow_zap_active": policy.allow_zap_active,
        "require_scope_validation": policy.require_scope_validation,
        "require_approval": policy.require_approval,
        "allowed_methods": list(policy.allowed_methods),
    }


def build_live_module_context(
    scan_id: str,
    project: AssessmentProject,
    config: LivePipelineConfig,
    metadata: dict[str, Any] | None = None,
) -> ModuleContext:
    validate_live_pipeline_config(config)
    safe_metadata = redact_sensitive_data(dict(metadata or {}))
    target = _target_from_metadata(project, safe_metadata if isinstance(safe_metadata, dict) else {})
    normalized_target, _ = _validate_target_in_scope(project, target)
    return ModuleContext(
        scan_id=scan_id,
        target=target,
        normalized_target=normalized_target,
        allowed_domains=list(project.scope.allowed_domains),
        allowed_ips=list(project.scope.allowed_ips),
        scan_mode=project.scan_mode,
        policy=_policy_to_dict(build_live_execution_policy(config)),
        metadata=safe_metadata if isinstance(safe_metadata, dict) else {},
    )


def build_safe_live_modules(config: LivePipelineConfig) -> list[Any]:
    validate_live_pipeline_config(config)
    module_map = {
        "live_dns": LiveDNSModule,
        "live_security_headers": LiveSecurityHeadersModule,
        "http_fingerprint": HTTPFingerprintModule,
        "robots_sitemap": RobotsSitemapModule,
    }
    return [module_map[name]() for name in config.enabled_modules]


def preflight_live_pipeline(
    project: AssessmentProject | None,
    config: LivePipelineConfig,
    target: str | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    try:
        validate_live_pipeline_config(config)
        if project is None:
            return False, "Assessment project is required for safe-live pipeline.", {}
        if not is_assessment_approved(project):
            return False, "Assessment project must be approved before safe-live pipeline runs.", {
                "assessment_id": project.metadata.assessment_id,
                "status": project.status,
            }
        if not config.safe_live:
            return False, "Safe-live mode is disabled.", {"safe_live": False}
        if not config.allow_network:
            return False, "Network access is disabled by live pipeline config.", {"allow_network": False}
        if config.kill_switch.enabled:
            reason = str(redact_sensitive_data(config.kill_switch.reason or "Kill switch is enabled."))
            return False, reason, {"kill_switch": True}
        requested_target = str(target or _default_project_target(project)).strip()
        scope = validate_scope(
            requested_target,
            allowed_domains=project.scope.allowed_domains,
            allowed_ips=project.scope.allowed_ips,
            denied_patterns=project.scope.denied_patterns,
        )
        if not scope.allowed:
            return False, scope.reason, {
                "target": requested_target,
                "normalized_target": scope.normalized_target,
            }
        return True, "Safe-live preflight passed.", {
            "assessment_id": project.metadata.assessment_id,
            "target": requested_target,
            "normalized_target": scope.normalized_target,
            "safe_live": config.safe_live,
            "allow_network": config.allow_network,
            "enabled_modules": list(config.enabled_modules),
        }
    except Exception as exc:
        return False, str(redact_sensitive_data(str(exc))), {}


def _audit_event(event_type: str, message: str, scan_id: str, target: str | None, status: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return audit_event_to_dict(
        create_audit_event(
            event_type,
            message,
            scan_id=scan_id,
            target=target,
            status=status,
            source="safe_live_pipeline",
            metadata=metadata,
        )
    )


def _execution_context(
    scan_id: str,
    target: str,
    project: AssessmentProject,
    config: LivePipelineConfig,
    metadata: dict[str, Any] | None,
) -> SafeExecutionContext:
    return SafeExecutionContext(
        scan_id=scan_id,
        target=target,
        allowed_domains=list(project.scope.allowed_domains),
        allowed_ips=list(project.scope.allowed_ips),
        scan_mode=project.scan_mode,
        budget=config.scan_budget,
        rate_limit=config.rate_limit,
        timeout=config.timeout,
        policy=build_live_execution_policy(config),
        kill_switch=config.kill_switch,
        metadata=redact_sensitive_data(metadata or {}),
    )


def _empty_result(
    scan_id: str,
    target: str | None,
    project: AssessmentProject | None,
    config: LivePipelineConfig,
    status: str,
    reason: str,
    started_at: str,
    audit_events: list[dict[str, Any]],
    execution_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scan_mode = project.scan_mode if project else "safe"
    result = {
        "scan_id": scan_id,
        "target": target,
        "normalized_target": target,
        "scan_mode": scan_mode,
        "safe_live": bool(config.safe_live),
        "allow_network": bool(config.allow_network),
        "status": status,
        "reason": reason,
        "allowed_scope": {
            "domains": list(project.scope.allowed_domains) if project else [],
            "ips": list(project.scope.allowed_ips) if project else [],
        },
        "assets": [],
        "endpoints": [],
        "findings": [],
        "deduped_findings": [],
        "evidence": [],
        "manual_testing_recommendations": [],
        "module_results": [],
        "audit_log": {
            "scan_id": scan_id,
            "target": target,
            "scan_mode": scan_mode,
            "modules_enabled": list(config.enabled_modules),
            "commands_executed": [],
            "errors": [reason],
            "findings_generated": 0,
        },
        "audit_events": audit_events,
        "execution_context": execution_context or {},
        "started_at": started_at,
        "ended_at": utc_now_iso(),
    }
    return redact_sensitive_data(result)


def _module_failure_result(name: str, reason: str) -> ModuleResult:
    return ModuleResult(module_name=name, status="failed", errors=[str(redact_sensitive_data(reason))], commands_executed=[])


def run_safe_live_pipeline(
    project: AssessmentProject | None,
    config: LivePipelineConfig | None = None,
    target: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    live_config = config or LivePipelineConfig()
    scan_id = generate_scan_id()
    started_at = utc_now_iso()
    safe_metadata = redact_sensitive_data(dict(metadata or {}))
    requested_target = str(redact_sensitive_data(target or "")).strip() or None
    audit_events: list[dict[str, Any]] = []
    try:
        allowed, reason, details = preflight_live_pipeline(project, live_config, target=requested_target)
        if not allowed:
            audit_events.append(_audit_event("scan_rejected", "Safe-live pipeline rejected", scan_id, requested_target, "rejected", details | {"reason": reason}))
            return _empty_result(scan_id, requested_target, project, live_config, "rejected", reason, started_at, audit_events)

        assert project is not None
        normalized_target = str(details.get("normalized_target") or requested_target or _default_project_target(project))
        execution_context = _execution_context(scan_id, normalized_target, project, live_config, safe_metadata if isinstance(safe_metadata, dict) else {})
        decision = create_execution_decision(
            "local:safe_live_pipeline",
            normalized_target,
            execution_context,
            state=ExecutionState(started_at=started_at),
            metadata={"enabled_modules": list(live_config.enabled_modules)},
        )
        if decision.audit_event:
            audit_events.append(decision.audit_event)
        if not decision.allowed:
            audit_events.append(_audit_event("scan_rejected", "Safe-live pipeline blocked by execution engine", scan_id, normalized_target, "rejected", {"reason": decision.reason}))
            return _empty_result(
                scan_id,
                normalized_target,
                project,
                live_config,
                "rejected",
                decision.reason,
                started_at,
                audit_events,
                safe_execution_context_to_dict(execution_context),
            )

        audit_events.append(_audit_event("scan_started", "Safe-live pipeline started", scan_id, normalized_target, "started", details))
        metadata_for_context = dict(safe_metadata if isinstance(safe_metadata, dict) else {})
        metadata_for_context["target"] = normalized_target
        module_context = build_live_module_context(scan_id, project, live_config, metadata_for_context)
        module_results = [run_module_safely(module, module_context) for module in build_safe_live_modules(live_config)]
        merged = merge_module_results(module_results)
        findings = list(merged["findings"])[: live_config.max_findings]

        scan_result_for_evidence = {
            "scan_id": scan_id,
            "target": normalized_target,
            "normalized_target": normalized_target,
            "assets": merged["assets"],
            "endpoints": merged["endpoints"],
            "findings": findings,
            "audit_events": audit_events,
        }
        evidence_items = collect_evidence_from_scan_result(scan_result_for_evidence)
        deduped = deduplicate_findings(findings, evidence_items=evidence_items)
        recommendations = generate_manual_testing_recommendations(findings, evidence_items=evidence_items)
        module_errors = list(merged["errors"])
        status = "partial_success" if any(result.status == "failed" for result in module_results) else "success"
        reason = "Safe-live pipeline completed with module errors." if status == "partial_success" else "Safe-live pipeline completed."
        audit_events.append(
            _audit_event(
                "scan_completed",
                "Safe-live pipeline completed",
                scan_id,
                normalized_target,
                status,
                {"module_statuses": merged["module_statuses"], "findings_generated": len(findings)},
            )
        )
        result = {
            "scan_id": scan_id,
            "target": normalized_target,
            "normalized_target": normalized_target,
            "scan_mode": project.scan_mode,
            "safe_live": True,
            "allow_network": True,
            "status": status,
            "reason": reason,
            "allowed_scope": {"domains": list(project.scope.allowed_domains), "ips": list(project.scope.allowed_ips)},
            "assets": merged["assets"],
            "endpoints": merged["endpoints"],
            "findings": findings,
            "deduped_findings": deduped_findings_to_dicts(deduped),
            "evidence": [evidence_item_to_dict(item) for item in evidence_items],
            "manual_testing_recommendations": [manual_test_recommendation_to_dict(item) for item in recommendations],
            "module_results": [module_result_to_dict(result) for result in module_results],
            "audit_log": {
                "scan_id": scan_id,
                "target": normalized_target,
                "scan_mode": project.scan_mode,
                "modules_enabled": list(live_config.enabled_modules),
                "commands_executed": [],
                "errors": module_errors,
                "findings_generated": len(findings),
            },
            "audit_events": audit_events,
            "execution_context": safe_execution_context_to_dict(execution_context),
            "execution_decision": execution_decision_to_dict(decision),
            "started_at": started_at,
            "ended_at": utc_now_iso(),
        }
        return redact_sensitive_data(result)
    except Exception as exc:
        reason = str(redact_sensitive_data(str(exc)))
        safe_target = requested_target or (str(target).strip() if target else None)
        audit_events.append(_audit_event("error", "Safe-live pipeline technical error", scan_id, safe_target, "error", {"reason": reason}))
        if project is not None and live_config.enabled_modules:
            module_result = _module_failure_result(str(live_config.enabled_modules[0]), reason)
            module_payload = [module_result_to_dict(module_result)]
        else:
            module_payload = []
        result = _empty_result(scan_id, safe_target, project, live_config, "error", reason, started_at, audit_events)
        result["module_results"] = module_payload
        return redact_sensitive_data(result)


def live_pipeline_result_summary(result: dict[str, Any]) -> dict[str, Any]:
    payload = result if isinstance(result, dict) else {}
    audit_log = payload.get("audit_log") if isinstance(payload.get("audit_log"), dict) else {}
    return {
        "scan_id": payload.get("scan_id"),
        "status": payload.get("status"),
        "target": payload.get("target"),
        "modules": len(payload.get("module_results") or []),
        "assets": len(payload.get("assets") or []),
        "endpoints": len(payload.get("endpoints") or []),
        "findings": len(payload.get("findings") or []),
        "deduped_findings": len(payload.get("deduped_findings") or []),
        "evidence": len(payload.get("evidence") or []),
        "manual_testing_recommendations": len(payload.get("manual_testing_recommendations") or []),
        "commands_executed": len(audit_log.get("commands_executed") or []),
    }
