from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import audit_event_to_dict, create_audit_event, redact_sensitive_data
from core.scope import validate_scope


SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}
DANGEROUS_ACTION_MARKERS = {
    "exploit",
    "bruteforce",
    "brute_force",
    "brute force",
    "credential_theft",
    "credential theft",
    "steal_cookie",
    "steal_token",
    "dos",
    "ddos",
    "fuzz_aggressive",
    "zap_active",
    "nmap_aggressive",
    "sqlmap",
    "reverse_shell",
    "persistence",
    "malware",
}


@dataclass(frozen=True)
class ScanBudget:
    max_requests: int = 50
    max_duration_seconds: int = 300
    max_concurrency: int = 2
    max_errors: int = 10


@dataclass(frozen=True)
class RateLimitConfig:
    requests_per_second: float = 0.5
    burst: int = 1


@dataclass(frozen=True)
class TimeoutConfig:
    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    total_timeout: float = 15.0


@dataclass(frozen=True)
class ExecutionPolicy:
    allow_network: bool = False
    allow_external_tools: bool = False
    allow_exploit: bool = False
    allow_bruteforce: bool = False
    allow_dos: bool = False
    allow_zap_active: bool = False
    require_scope_validation: bool = True
    require_approval: bool = True
    allowed_methods: tuple[str, ...] = ("GET", "HEAD")


@dataclass(frozen=True)
class KillSwitch:
    enabled: bool = False
    reason: str = ""


@dataclass
class ExecutionState:
    started_at: str
    requests_made: int = 0
    errors_seen: int = 0
    active_tasks: int = 0


@dataclass(frozen=True)
class ExecutionDecision:
    allowed: bool
    reason: str
    action: str
    target: str | None = None
    requires_scope: bool = True
    audit_event: dict[str, Any] | None = None


@dataclass(frozen=True)
class SafeExecutionContext:
    scan_id: str
    target: str
    allowed_domains: list[str]
    allowed_ips: list[str] = field(default_factory=list)
    scan_mode: str = "safe"
    budget: ScanBudget = field(default_factory=ScanBudget)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    timeout: TimeoutConfig = field(default_factory=TimeoutConfig)
    policy: ExecutionPolicy = field(default_factory=ExecutionPolicy)
    kill_switch: KillSwitch = field(default_factory=KillSwitch)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_domains", list(self.allowed_domains or []))
        object.__setattr__(self, "allowed_ips", list(self.allowed_ips or []))
        object.__setattr__(self, "metadata", sanitize_action_metadata(self.metadata))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _ensure_range(value: int | float, field_name: str, minimum: int | float, maximum: int | float) -> None:
    if value < minimum or value > maximum:
        raise ValueError(f"{field_name} must be between {minimum} and {maximum}.")


def validate_scan_budget(budget: ScanBudget) -> None:
    _ensure_range(int(budget.max_requests), "max_requests", 1, 1000)
    _ensure_range(int(budget.max_duration_seconds), "max_duration_seconds", 1, 3600)
    _ensure_range(int(budget.max_concurrency), "max_concurrency", 1, 10)
    _ensure_range(int(budget.max_errors), "max_errors", 0, 100)


def validate_rate_limit_config(config: RateLimitConfig) -> None:
    _ensure_range(float(config.requests_per_second), "requests_per_second", 0.000001, 10)
    _ensure_range(int(config.burst), "burst", 1, 20)


def validate_timeout_config(config: TimeoutConfig) -> None:
    if config.connect_timeout <= 0 or config.read_timeout <= 0 or config.total_timeout <= 0:
        raise ValueError("Timeout values must be greater than zero.")
    if config.total_timeout < config.connect_timeout or config.total_timeout < config.read_timeout:
        raise ValueError("total_timeout must be greater than or equal to connect and read timeouts.")
    if config.total_timeout > 120:
        raise ValueError("total_timeout must not exceed 120 seconds.")


def validate_execution_policy(policy: ExecutionPolicy) -> None:
    if policy.allow_exploit:
        raise ValueError("Exploit actions are prohibited.")
    if policy.allow_bruteforce:
        raise ValueError("Brute force actions are prohibited.")
    if policy.allow_dos:
        raise ValueError("Denial-of-service actions are prohibited.")
    if policy.allow_zap_active:
        raise ValueError("Active ZAP scan is prohibited.")
    methods = {str(method or "").strip().upper() for method in policy.allowed_methods}
    if not methods or not methods.issubset(SAFE_HTTP_METHODS):
        raise ValueError("Execution policy allowed_methods may only include GET, HEAD, or OPTIONS.")


def check_kill_switch(kill_switch: KillSwitch) -> ExecutionDecision | None:
    if kill_switch.enabled:
        reason = str(redact_sensitive_data(kill_switch.reason or "Kill switch is enabled."))
        return ExecutionDecision(False, reason, "kill_switch", requires_scope=False)
    return None


def check_scan_budget(
    budget: ScanBudget,
    state: ExecutionState,
    elapsed_seconds: float,
) -> ExecutionDecision | None:
    if state.requests_made >= budget.max_requests:
        return ExecutionDecision(False, "Scan request budget exhausted.", "budget", requires_scope=False)
    if elapsed_seconds >= budget.max_duration_seconds:
        return ExecutionDecision(False, "Scan duration budget exceeded.", "budget", requires_scope=False)
    if state.active_tasks >= budget.max_concurrency:
        return ExecutionDecision(False, "Scan concurrency limit reached.", "budget", requires_scope=False)
    if state.errors_seen >= budget.max_errors:
        return ExecutionDecision(False, "Scan error budget exhausted.", "budget", requires_scope=False)
    return None


def enforce_scope_before_action(
    target: str,
    allowed_domains: list[str],
    allowed_ips: list[str] | None = None,
) -> ExecutionDecision:
    result = validate_scope(target, allowed_domains=allowed_domains, allowed_ips=allowed_ips)
    if result.allowed:
        return ExecutionDecision(True, result.reason, "scope_validation", target=result.normalized_target)
    return ExecutionDecision(False, result.reason, "scope_validation", target=result.normalized_target)


def sanitize_action_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    sanitized = redact_sensitive_data(dict(metadata or {}))
    return sanitized if isinstance(sanitized, dict) else {}


def is_dangerous_action(action: str) -> bool:
    normalized = str(action or "").strip().lower().replace("-", "_")
    spaced = normalized.replace("_", " ")
    return any(marker in normalized or marker in spaced for marker in DANGEROUS_ACTION_MARKERS)


def _is_network_action(action: str) -> bool:
    return str(action or "").strip().lower().startswith("network:")


def _is_external_tool_action(action: str) -> bool:
    return str(action or "").strip().lower().startswith("tool:")


def _with_audit_event(
    decision: ExecutionDecision,
    context: SafeExecutionContext,
    metadata: dict[str, Any] | None = None,
) -> ExecutionDecision:
    event = record_execution_audit_event(decision.action, decision, context, metadata=metadata)
    return ExecutionDecision(
        allowed=decision.allowed,
        reason=decision.reason,
        action=decision.action,
        target=decision.target,
        requires_scope=decision.requires_scope,
        audit_event=event,
    )


def create_execution_decision(
    action: str,
    target: str | None,
    context: SafeExecutionContext,
    state: ExecutionState | None = None,
    elapsed_seconds: float = 0,
    metadata: dict[str, Any] | None = None,
) -> ExecutionDecision:
    validate_scan_budget(context.budget)
    validate_rate_limit_config(context.rate_limit)
    validate_timeout_config(context.timeout)
    validate_execution_policy(context.policy)

    safe_action = str(redact_sensitive_data(action or "")).strip()
    safe_target = str(redact_sensitive_data(target or context.target or "")).strip() or None
    safe_metadata = sanitize_action_metadata(metadata)

    if is_dangerous_action(safe_action):
        return _with_audit_event(
            ExecutionDecision(False, "Dangerous action is blocked.", safe_action, target=safe_target),
            context,
            safe_metadata,
        )

    kill_decision = check_kill_switch(context.kill_switch)
    if kill_decision is not None:
        return _with_audit_event(
            ExecutionDecision(False, kill_decision.reason, safe_action, target=safe_target, requires_scope=False),
            context,
            safe_metadata,
        )

    budget_decision = check_scan_budget(
        context.budget,
        state or ExecutionState(started_at=utc_now_iso()),
        elapsed_seconds,
    )
    if budget_decision is not None:
        return _with_audit_event(
            ExecutionDecision(False, budget_decision.reason, safe_action, target=safe_target, requires_scope=False),
            context,
            safe_metadata,
        )

    if context.policy.require_scope_validation and safe_target:
        scope_decision = enforce_scope_before_action(safe_target, context.allowed_domains, context.allowed_ips)
        if not scope_decision.allowed:
            return _with_audit_event(
                ExecutionDecision(False, scope_decision.reason, safe_action, target=scope_decision.target),
                context,
                safe_metadata,
            )

    if _is_network_action(safe_action) and not context.policy.allow_network:
        return _with_audit_event(
            ExecutionDecision(False, "Network actions are disabled by execution policy.", safe_action, target=safe_target),
            context,
            safe_metadata,
        )

    if _is_external_tool_action(safe_action) and not context.policy.allow_external_tools:
        return _with_audit_event(
            ExecutionDecision(False, "External tool actions are disabled by execution policy.", safe_action, target=safe_target),
            context,
            safe_metadata,
        )

    return _with_audit_event(
        ExecutionDecision(True, "Action allowed by safe execution guardrails.", safe_action, target=safe_target),
        context,
        safe_metadata,
    )


def record_execution_audit_event(
    action: str,
    decision: ExecutionDecision,
    context: SafeExecutionContext,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event = create_audit_event(
        "dashboard_action",
        "Execution decision created",
        scan_id=context.scan_id,
        target=decision.target or context.target,
        status="allowed" if decision.allowed else "blocked",
        source="execution_engine",
        metadata={
            "action": action,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "scan_mode": context.scan_mode,
            "metadata": sanitize_action_metadata(metadata),
        },
    )
    return audit_event_to_dict(event)


def execution_decision_to_dict(decision: ExecutionDecision) -> dict[str, Any]:
    return redact_sensitive_data(asdict(decision))


def safe_execution_context_to_dict(context: SafeExecutionContext) -> dict[str, Any]:
    return redact_sensitive_data(asdict(context))
