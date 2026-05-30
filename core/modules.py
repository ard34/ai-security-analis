from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from core.logging import redact_sensitive_data


VALID_MODULE_STATUSES = {"success", "skipped", "failed"}
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_CONFIDENCES = {"low", "medium", "high"}
DANGEROUS_POLICY_FLAGS = ("allow_exploit", "allow_bruteforce", "allow_zap_active")


@dataclass(frozen=True)
class ModuleContext:
    scan_id: str
    target: str
    normalized_target: str
    allowed_domains: list[str]
    allowed_ips: list[str]
    scan_mode: str
    policy: dict[str, Any]
    assets: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "target", redact_sensitive_data(self.target))
        object.__setattr__(self, "normalized_target", redact_sensitive_data(self.normalized_target))
        object.__setattr__(self, "allowed_domains", list(self.allowed_domains or []))
        object.__setattr__(self, "allowed_ips", list(self.allowed_ips or []))
        object.__setattr__(self, "policy", redact_sensitive_data(dict(self.policy or {})))
        object.__setattr__(self, "assets", redact_sensitive_data(list(self.assets or [])))
        object.__setattr__(self, "endpoints", redact_sensitive_data(list(self.endpoints or [])))
        object.__setattr__(self, "metadata", redact_sensitive_data(dict(self.metadata or {})))


@dataclass
class ModuleResult:
    module_name: str
    status: Literal["success", "skipped", "failed"]
    assets: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    commands_executed: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.module_name = redact_sensitive_data(self.module_name)
        self.assets = redact_sensitive_data(list(self.assets or []))
        self.endpoints = redact_sensitive_data(list(self.endpoints or []))
        self.findings = redact_sensitive_data(list(self.findings or []))
        self.evidence = redact_sensitive_data(list(self.evidence or []))
        self.errors = redact_sensitive_data([str(error) for error in (self.errors or [])])
        self.commands_executed = redact_sensitive_data(list(self.commands_executed or []))
        self.metadata = redact_sensitive_data(dict(self.metadata or {}))


class BaseReconModule(ABC):
    name: str
    description: str
    required_policy_flags: tuple[str, ...] = ()

    @abstractmethod
    def run(self, context: ModuleContext) -> ModuleResult:
        ...


def validate_module_name(name: str) -> str:
    normalized = str(name or "").strip()
    if not normalized:
        raise ValueError("Module name must be a non-empty string.")
    if normalized != normalized.lower():
        raise ValueError("Module name must be lowercase.")
    if any(character in normalized for character in (" ", "/", "\\", ".", ":")):
        raise ValueError("Module name contains invalid characters.")
    if not all(character.islower() or character.isdigit() or character == "_" for character in normalized):
        raise ValueError("Module name may only contain lowercase letters, numbers, and underscores.")
    return normalized


def _ensure_list(value: Any, field_name: str) -> None:
    if not isinstance(value, list):
        raise ValueError(f"Module result {field_name} must be a list.")


def validate_module_result(result: ModuleResult) -> None:
    validate_module_name(result.module_name)
    if result.status not in VALID_MODULE_STATUSES:
        raise ValueError(f"Invalid module result status: {result.status}")

    _ensure_list(result.assets, "assets")
    _ensure_list(result.endpoints, "endpoints")
    _ensure_list(result.findings, "findings")
    _ensure_list(result.evidence, "evidence")
    _ensure_list(result.errors, "errors")
    _ensure_list(result.commands_executed, "commands_executed")

    if result.commands_executed:
        raise ValueError("Module command execution is disabled for this stage.")

    for index, finding in enumerate(result.findings):
        if not isinstance(finding, dict):
            raise ValueError(f"Module finding at index {index} must be a dict.")
        if finding.get("is_potential") is not True:
            raise ValueError(f"Module finding at index {index} must be potential.")
        if "severity" in finding and finding.get("severity") not in VALID_SEVERITIES:
            raise ValueError(f"Module finding at index {index} has invalid severity.")
        if "confidence" in finding and finding.get("confidence") not in VALID_CONFIDENCES:
            raise ValueError(f"Module finding at index {index} has invalid confidence.")

    sanitized_metadata = redact_sensitive_data(result.metadata)
    if sanitized_metadata != result.metadata:
        raise ValueError("Module result metadata must be sanitized.")


def _reject_dangerous_policy(policy: dict[str, Any]) -> None:
    for flag in DANGEROUS_POLICY_FLAGS:
        if bool(policy.get(flag, False)):
            raise ValueError(f"Dangerous policy flag cannot be enabled: {flag}")


def is_module_allowed(module: BaseReconModule, policy: dict[str, Any]) -> bool:
    _reject_dangerous_policy(policy)
    required_flags = tuple(getattr(module, "required_policy_flags", ()) or ())
    if not required_flags:
        return True
    return all(bool(policy.get(flag, False)) for flag in required_flags)


def run_module_safely(module: BaseReconModule, context: ModuleContext) -> ModuleResult:
    module_name = validate_module_name(module.name)
    try:
        if not is_module_allowed(module, context.policy):
            result = ModuleResult(
                module_name=module_name,
                status="skipped",
                metadata={"reason": "required policy flags are not enabled"},
            )
            validate_module_result(result)
            return result

        result = module.run(context)
        result.commands_executed = []
        result.module_name = module_name
        result.assets = redact_sensitive_data(result.assets)
        result.endpoints = redact_sensitive_data(result.endpoints)
        result.findings = redact_sensitive_data(result.findings)
        result.evidence = redact_sensitive_data(result.evidence)
        result.errors = redact_sensitive_data(result.errors)
        result.metadata = redact_sensitive_data(result.metadata)
        validate_module_result(result)
        return result
    except Exception as exc:
        safe_error = str(redact_sensitive_data(str(exc)))
        result = ModuleResult(module_name=module_name, status="failed", errors=[safe_error], commands_executed=[])
        validate_module_result(result)
        return result


def module_result_to_dict(result: ModuleResult) -> dict[str, Any]:
    validate_module_result(result)
    return redact_sensitive_data(asdict(result))


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            merged.append(item)
    return merged


def merge_module_results(results: list[ModuleResult]) -> dict[str, Any]:
    assets: list[str] = []
    endpoints: list[str] = []
    findings: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    errors: list[str] = []
    modules: list[str] = []
    module_statuses: dict[str, str] = {}

    for result in results:
        validate_module_result(result)
        assets.extend(result.assets)
        endpoints.extend(result.endpoints)
        findings.extend(result.findings)
        evidence.extend(result.evidence)
        errors.extend(result.errors)
        modules.append(result.module_name)
        module_statuses[result.module_name] = result.status

    return redact_sensitive_data(
        {
            "assets": _unique(assets),
            "endpoints": _unique(endpoints),
            "findings": findings,
            "evidence": evidence,
            "errors": errors,
            "commands_executed": [],
            "modules": _unique(modules),
            "module_statuses": module_statuses,
        }
    )
