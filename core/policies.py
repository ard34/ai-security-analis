from __future__ import annotations

from copy import deepcopy
from typing import Any


DANGEROUS_CAPABILITIES = {"allow_zap_active", "allow_bruteforce", "allow_exploit"}

SCAN_MODES: dict[str, dict[str, Any]] = {
    "strict": {
        "allow_subdomain_enum": True,
        "allow_dns_lookup": True,
        "allow_live_check": True,
        "allow_port_scan": False,
        "allow_katana": False,
        "allow_zap_passive": True,
        "allow_zap_active": False,
        "allow_nuclei_safe": False,
        "allow_bruteforce": False,
        "allow_exploit": False,
        "rate_limit": "very_low",
    },
    "safe": {
        "allow_subdomain_enum": True,
        "allow_dns_lookup": True,
        "allow_live_check": True,
        "allow_port_scan": True,
        "allow_katana": True,
        "allow_zap_passive": True,
        "allow_zap_active": False,
        "allow_nuclei_safe": True,
        "allow_bruteforce": False,
        "allow_exploit": False,
        "rate_limit": "low",
    },
    "standard": {
        "allow_subdomain_enum": True,
        "allow_dns_lookup": True,
        "allow_live_check": True,
        "allow_port_scan": True,
        "allow_katana": True,
        "allow_zap_passive": True,
        "allow_zap_active": False,
        "allow_nuclei_safe": True,
        "allow_bruteforce": False,
        "allow_exploit": False,
        "rate_limit": "medium",
    },
}


class PolicyError(ValueError):
    pass


def get_scan_policy(mode: str) -> dict[str, Any]:
    key = str(mode or "").strip().lower()
    if key not in SCAN_MODES:
        raise PolicyError(f"Unknown scan mode: {mode}")
    policy = deepcopy(SCAN_MODES[key])
    for capability in DANGEROUS_CAPABILITIES:
        policy[capability] = False
    return policy


def validate_requested_policy(mode: str, requested_overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = get_scan_policy(mode)
    for key, value in (requested_overrides or {}).items():
        if key in DANGEROUS_CAPABILITIES and bool(value):
            raise PolicyError(f"Capability is prohibited and cannot be enabled: {key}")
        if key in policy:
            policy[key] = value
    for capability in DANGEROUS_CAPABILITIES:
        if policy.get(capability):
            raise PolicyError(f"Unsafe policy attempted to enable: {capability}")
        policy[capability] = False
    return policy


def assert_tool_allowed(policy: dict[str, Any], capability: str) -> None:
    if capability in DANGEROUS_CAPABILITIES:
        raise PolicyError(f"Capability is prohibited: {capability}")
    if not bool(policy.get(capability, False)):
        raise PolicyError(f"Capability is not allowed by current scan policy: {capability}")

