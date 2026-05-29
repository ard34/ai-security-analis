from __future__ import annotations

import pytest

from core.policies import DANGEROUS_CAPABILITIES, SCAN_MODES, PolicyError, get_scan_policy, validate_requested_policy


def test_strict_mode_exists() -> None:
    assert "strict" in SCAN_MODES


def test_safe_mode_exists() -> None:
    assert "safe" in SCAN_MODES


def test_standard_mode_exists() -> None:
    assert "standard" in SCAN_MODES


@pytest.mark.parametrize("mode", ["strict", "safe", "standard"])
def test_dangerous_capabilities_are_always_disabled(mode: str) -> None:
    policy = get_scan_policy(mode)
    for capability in DANGEROUS_CAPABILITIES:
        assert policy[capability] is False


@pytest.mark.parametrize("capability", sorted(DANGEROUS_CAPABILITIES))
def test_policy_rejects_attempt_to_enable_dangerous_capability(capability: str) -> None:
    with pytest.raises(PolicyError):
        validate_requested_policy("safe", {capability: True})


def test_unknown_policy_mode_rejected() -> None:
    with pytest.raises(PolicyError):
        get_scan_policy("aggressive")


def test_policy_cannot_be_made_dangerous_with_multiple_overrides() -> None:
    with pytest.raises(PolicyError):
        validate_requested_policy(
            "standard",
            {
                "allow_zap_active": True,
                "allow_bruteforce": True,
                "allow_exploit": True,
            },
        )
