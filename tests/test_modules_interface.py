from __future__ import annotations

import os
import socket
import subprocess

import pytest

from core.modules import (
    BaseReconModule,
    ModuleContext,
    ModuleResult,
    is_module_allowed,
    merge_module_results,
    module_result_to_dict,
    run_module_safely,
    validate_module_name,
    validate_module_result,
)
from modules.dummy_module import DummyPassiveModule


def make_context(policy: dict | None = None, metadata: dict | None = None) -> ModuleContext:
    return ModuleContext(
        scan_id="scan-001",
        target="example.com",
        normalized_target="example.com",
        allowed_domains=["example.com"],
        allowed_ips=[],
        scan_mode="safe",
        policy=policy
        or {
            "allow_exploit": False,
            "allow_bruteforce": False,
            "allow_zap_active": False,
            "allow_dns_lookup": True,
        },
        metadata=metadata or {},
    )


def make_result(**overrides) -> ModuleResult:
    payload = {
        "module_name": "dummy_passive",
        "status": "success",
        "findings": [
            {
                "module": "dummy_passive",
                "finding_type": "informational",
                "title": "Dummy Passive Observation",
                "severity": "info",
                "confidence": "low",
                "evidence": "safe",
                "recommendation": "safe",
                "source": "test",
                "is_potential": True,
            }
        ],
    }
    payload.update(overrides)
    return ModuleResult(**payload)


class FlaggedModule(DummyPassiveModule):
    name = "flagged_module"
    required_policy_flags = ("allow_dns_lookup",)


class ErrorModule(DummyPassiveModule):
    name = "error_module"

    def run(self, context: ModuleContext) -> ModuleResult:
        raise RuntimeError("boom token=abc")


def test_validate_module_name_accepts_security_headers() -> None:
    assert validate_module_name("security_headers") == "security_headers"


def test_validate_module_name_accepts_dummy_passive() -> None:
    assert validate_module_name("dummy_passive") == "dummy_passive"


def test_validate_module_name_rejects_empty() -> None:
    with pytest.raises(ValueError):
        validate_module_name("")


def test_validate_module_name_rejects_uppercase() -> None:
    with pytest.raises(ValueError):
        validate_module_name("Security_Headers")


def test_validate_module_name_rejects_space() -> None:
    with pytest.raises(ValueError):
        validate_module_name("security headers")


def test_validate_module_name_rejects_path_traversal() -> None:
    with pytest.raises(ValueError):
        validate_module_name("../evil")


def test_validate_module_name_rejects_dot() -> None:
    with pytest.raises(ValueError):
        validate_module_name("evil.module")


def test_module_context_can_be_created() -> None:
    context = make_context()

    assert context.scan_id == "scan-001"
    assert context.normalized_target == "example.com"


def test_module_result_default_commands_executed_is_empty() -> None:
    result = ModuleResult(module_name="dummy_passive", status="success")

    assert result.commands_executed == []


def test_validate_module_result_accepts_valid_result() -> None:
    validate_module_result(make_result())


def test_validate_module_result_rejects_invalid_status() -> None:
    with pytest.raises(ValueError):
        validate_module_result(make_result(status="invalid"))


def test_validate_module_result_rejects_non_empty_commands_executed() -> None:
    with pytest.raises(ValueError):
        validate_module_result(make_result(commands_executed=["curl https://example.com"]))


def test_validate_module_result_rejects_non_potential_finding() -> None:
    result = make_result(findings=[{"is_potential": False}])

    with pytest.raises(ValueError):
        validate_module_result(result)


def test_validate_module_result_rejects_invalid_severity() -> None:
    result = make_result(findings=[{"is_potential": True, "severity": "urgent"}])

    with pytest.raises(ValueError):
        validate_module_result(result)


def test_validate_module_result_rejects_invalid_confidence() -> None:
    result = make_result(findings=[{"is_potential": True, "confidence": "certain"}])

    with pytest.raises(ValueError):
        validate_module_result(result)


def test_is_module_allowed_true_without_required_flags() -> None:
    assert is_module_allowed(DummyPassiveModule(), make_context().policy) is True


def test_is_module_allowed_false_when_required_flag_false() -> None:
    policy = make_context({"allow_exploit": False, "allow_bruteforce": False, "allow_zap_active": False, "allow_dns_lookup": False}).policy

    assert is_module_allowed(FlaggedModule(), policy) is False


def test_is_module_allowed_true_when_required_flag_true() -> None:
    assert is_module_allowed(FlaggedModule(), make_context().policy) is True


def test_is_module_allowed_rejects_allow_exploit_true() -> None:
    with pytest.raises(ValueError):
        is_module_allowed(DummyPassiveModule(), {"allow_exploit": True, "allow_bruteforce": False, "allow_zap_active": False})


def test_is_module_allowed_rejects_allow_bruteforce_true() -> None:
    with pytest.raises(ValueError):
        is_module_allowed(DummyPassiveModule(), {"allow_exploit": False, "allow_bruteforce": True, "allow_zap_active": False})


def test_is_module_allowed_rejects_allow_zap_active_true() -> None:
    with pytest.raises(ValueError):
        is_module_allowed(DummyPassiveModule(), {"allow_exploit": False, "allow_bruteforce": False, "allow_zap_active": True})


def test_run_module_safely_runs_dummy_module() -> None:
    result = run_module_safely(DummyPassiveModule(), make_context())

    assert result.status == "success"
    assert result.module_name == "dummy_passive"


def test_run_module_safely_returns_skipped_when_policy_flag_not_allowed() -> None:
    context = make_context({"allow_exploit": False, "allow_bruteforce": False, "allow_zap_active": False, "allow_dns_lookup": False})

    result = run_module_safely(FlaggedModule(), context)

    assert result.status == "skipped"


def test_run_module_safely_returns_failed_when_module_raises() -> None:
    result = run_module_safely(ErrorModule(), make_context())

    assert result.status == "failed"
    assert result.errors


def test_run_module_safely_redacts_secret_in_error_and_metadata() -> None:
    result = run_module_safely(ErrorModule(), make_context(metadata={"token": "abc"}))
    payload = module_result_to_dict(result)

    assert "token=abc" not in str(payload)
    assert "token=[REDACTED]" in str(payload)


def test_module_result_to_dict_returns_dict() -> None:
    assert isinstance(module_result_to_dict(make_result()), dict)


def test_merge_module_results_merges_unique_assets() -> None:
    merged = merge_module_results(
        [
            make_result(assets=["https://example.com"]),
            make_result(assets=["https://example.com", "https://app.example.com"]),
        ]
    )

    assert merged["assets"] == ["https://example.com", "https://app.example.com"]


def test_merge_module_results_merges_unique_endpoints() -> None:
    merged = merge_module_results([make_result(endpoints=["/"]), make_result(endpoints=["/", "/login"])])

    assert merged["endpoints"] == ["/", "/login"]


def test_merge_module_results_merges_findings() -> None:
    merged = merge_module_results([make_result(), make_result(module_name="security_headers")])

    assert len(merged["findings"]) == 2


def test_merge_module_results_sets_module_statuses() -> None:
    merged = merge_module_results([make_result(), ModuleResult(module_name="security_headers", status="skipped")])

    assert merged["module_statuses"] == {"dummy_passive": "success", "security_headers": "skipped"}


def test_dummy_module_generates_potential_finding() -> None:
    result = run_module_safely(DummyPassiveModule(), make_context())

    assert result.findings[0]["is_potential"] is True


def test_dummy_module_does_not_use_network(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in module interface")

    monkeypatch.setattr(socket, "socket", fail_socket)

    result = run_module_safely(DummyPassiveModule(), make_context())

    assert result.status == "success"


def test_module_interface_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in module interface")

    monkeypatch.setattr(subprocess, "run", fail_run)

    result = run_module_safely(DummyPassiveModule(), make_context())

    assert result.status == "success"


def test_module_interface_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in module interface")

    monkeypatch.setattr(os, "system", fail_system)

    result = run_module_safely(DummyPassiveModule(), make_context())

    assert result.status == "success"


def test_module_interface_base_class_requires_run() -> None:
    with pytest.raises(TypeError):
        BaseReconModule()
