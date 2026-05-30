from __future__ import annotations

import inspect
import os
import socket
import subprocess

import pytest

from core.assessment import approve_assessment_project, create_assessment_project
from core.execution import KillSwitch
from core.live_pipeline import (
    LivePipelineConfig,
    build_live_execution_policy,
    build_safe_live_modules,
    live_pipeline_result_summary,
    preflight_live_pipeline,
    run_safe_live_pipeline,
    validate_live_pipeline_config,
)


class FakeHTTPResponse:
    def __init__(self, status=200, headers=None, body=b"OK", url="https://example.com"):
        self.status = status
        self.headers = headers or {
            "Content-Type": "text/html",
            "Server": "fake-server",
        }
        self._body = body
        self.url = url

    def read(self, n=-1):
        return self._body if n == -1 else self._body[:n]

    def geturl(self):
        return self.url


class MultiResponseFakeOpener:
    def __init__(self, responses_by_url=None):
        self.responses_by_url = responses_by_url or {}
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        url = getattr(request, "full_url", str(request))
        return self.responses_by_url.get(url, FakeHTTPResponse(url=url))


def fake_getaddrinfo(name, port, family=0, type=0, proto=0, flags=0):
    value = "2001:db8::1" if family == socket.AF_INET6 else "93.184.216.34"
    return [(family, type, proto, "", (value, 0))]


def make_approved_project():
    project = create_assessment_project(
        name="Preprod Web Assessment",
        owner="Security Team",
        operator="Pentester",
        authorization_note="Authorized internal pre-production assessment.",
        allowed_domains=["example.com"],
        environment="preprod",
        scan_mode="safe",
    )
    return approve_assessment_project(project)


def make_draft_project():
    return create_assessment_project(
        name="Preprod Web Assessment",
        owner="Security Team",
        operator="Pentester",
        authorization_note="Authorized internal pre-production assessment.",
        allowed_domains=["example.com"],
        environment="preprod",
        scan_mode="safe",
    )


def make_metadata(**overrides):
    metadata = {
        "http_opener": MultiResponseFakeOpener(
            {
                "https://example.com/robots.txt": FakeHTTPResponse(body=b"User-agent: *\nDisallow: /admin\nAllow: /public\n"),
                "https://example.com/sitemap.xml": FakeHTTPResponse(body=b"<urlset><url><loc>https://example.com/docs</loc></url></urlset>"),
            }
        ),
        "dns_resolver": fake_getaddrinfo,
        "url": "https://example.com",
        "base_url": "https://example.com",
        "dns_record_types": ["A", "AAAA"],
    }
    metadata.update(overrides)
    return metadata


def test_default_config_safe_live_false() -> None:
    assert LivePipelineConfig().safe_live is False


def test_default_allow_network_false() -> None:
    assert LivePipelineConfig().allow_network is False


def test_config_rejects_unknown_module() -> None:
    with pytest.raises(ValueError):
        validate_live_pipeline_config(LivePipelineConfig(enabled_modules=("unknown",)))


def test_config_rejects_invalid_max_findings() -> None:
    with pytest.raises(ValueError):
        validate_live_pipeline_config(LivePipelineConfig(max_findings=0))


def test_build_live_execution_policy_disables_dangerous_flags() -> None:
    policy = build_live_execution_policy(LivePipelineConfig(safe_live=True, allow_network=True))

    assert policy.allow_external_tools is False
    assert policy.allow_exploit is False
    assert policy.allow_bruteforce is False
    assert policy.allow_dos is False
    assert policy.allow_zap_active is False


def test_policy_allows_network_only_when_config_allow_network_true() -> None:
    assert build_live_execution_policy(LivePipelineConfig(allow_network=False)).allow_network is False
    assert build_live_execution_policy(LivePipelineConfig(allow_network=True)).allow_network is True


def test_build_safe_live_modules_returns_enabled_modules() -> None:
    modules = build_safe_live_modules(LivePipelineConfig(enabled_modules=("live_dns", "http_fingerprint")))

    assert [module.name for module in modules] == ["live_dns", "http_fingerprint"]


def test_build_safe_live_modules_rejects_non_allowlisted_module() -> None:
    with pytest.raises(ValueError):
        build_safe_live_modules(LivePipelineConfig(enabled_modules=("tool_nmap",)))


def test_preflight_rejects_missing_project() -> None:
    allowed, reason, _ = preflight_live_pipeline(None, LivePipelineConfig(safe_live=True, allow_network=True))

    assert allowed is False
    assert "project" in reason.lower()


def test_preflight_rejects_draft_assessment() -> None:
    allowed, reason, _ = preflight_live_pipeline(make_draft_project(), LivePipelineConfig(safe_live=True, allow_network=True))

    assert allowed is False
    assert "approved" in reason.lower()


def test_preflight_rejects_safe_live_false() -> None:
    allowed, reason, _ = preflight_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=False, allow_network=True))

    assert allowed is False
    assert "disabled" in reason.lower()


def test_preflight_rejects_allow_network_false() -> None:
    allowed, reason, _ = preflight_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=False))

    assert allowed is False
    assert "network" in reason.lower()


def test_preflight_rejects_out_of_scope_target() -> None:
    allowed, _, _ = preflight_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="evil.com")

    assert allowed is False


def test_preflight_rejects_lookalike_target() -> None:
    allowed, _, _ = preflight_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com.evil.com")

    assert allowed is False


def test_preflight_rejects_kill_switch_enabled() -> None:
    config = LivePipelineConfig(safe_live=True, allow_network=True, kill_switch=KillSwitch(enabled=True, reason="manual stop"))

    allowed, reason, _ = preflight_live_pipeline(make_approved_project(), config)

    assert allowed is False
    assert "stop" in reason


def test_preflight_accepts_approved_assessment_with_safe_live_and_network() -> None:
    allowed, reason, details = preflight_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com")

    assert allowed is True
    assert reason
    assert details["normalized_target"] == "example.com"


def test_run_safe_live_pipeline_rejected_when_no_project() -> None:
    result = run_safe_live_pipeline(None, LivePipelineConfig(safe_live=True, allow_network=True), target="example.com")

    assert result["status"] == "rejected"


def test_rejected_result_has_audit_events() -> None:
    result = run_safe_live_pipeline(None, LivePipelineConfig(safe_live=True, allow_network=True), target="example.com")

    assert result["audit_events"]


def test_rejected_result_has_commands_executed_empty() -> None:
    result = run_safe_live_pipeline(None, LivePipelineConfig(safe_live=True, allow_network=True), target="example.com")

    assert result["audit_log"]["commands_executed"] == []


def test_approved_project_with_mocked_modules_returns_success() -> None:
    result = run_safe_live_pipeline(
        make_approved_project(),
        LivePipelineConfig(safe_live=True, allow_network=True),
        target="example.com",
        metadata=make_metadata(),
    )

    assert result["status"] in {"success", "partial_success"}


def test_success_result_has_assets() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["assets"]


def test_success_result_has_endpoints() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert "/admin" in result["endpoints"]


def test_success_result_has_findings_or_deduped_findings() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["findings"] or result["deduped_findings"]


def test_success_result_has_evidence() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["evidence"]


def test_success_result_has_manual_testing_recommendations() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["manual_testing_recommendations"]


def test_success_result_has_module_results() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["module_results"]


def test_success_result_has_execution_context() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["execution_context"]["target"] == "example.com"


def test_success_result_commands_executed_empty() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["audit_log"]["commands_executed"] == []


def test_module_failure_returns_partial_success_or_errors() -> None:
    result = run_safe_live_pipeline(
        make_approved_project(),
        LivePipelineConfig(safe_live=True, allow_network=True, enabled_modules=("robots_sitemap",)),
        target="example.com",
        metadata={"http_opener": MultiResponseFakeOpener({}), "base_url": "https://evil.com"},
    )

    assert result["status"] in {"partial_success", "error"}
    assert result["audit_log"]["errors"] or result["module_results"]


def test_findings_capped_by_max_findings() -> None:
    result = run_safe_live_pipeline(
        make_approved_project(),
        LivePipelineConfig(safe_live=True, allow_network=True, max_findings=1),
        target="example.com",
        metadata=make_metadata(),
    )

    assert len(result["findings"]) <= 1


def test_metadata_sanitized_no_token_or_password_present() -> None:
    result = run_safe_live_pipeline(
        make_approved_project(),
        LivePipelineConfig(safe_live=True, allow_network=True),
        target="example.com",
        metadata=make_metadata(token="abc", password="secret"),
    )

    text = str(result)
    assert "abc" not in text
    assert "secret" not in text
    assert "[REDACTED]" in text


def test_result_summary_counts_fields_correctly() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())
    summary = live_pipeline_result_summary(result)

    assert summary["modules"] == len(result["module_results"])
    assert summary["assets"] == len(result["assets"])
    assert summary["commands_executed"] == 0


def test_pipeline_does_not_run_unknown_module() -> None:
    result = run_safe_live_pipeline(
        make_approved_project(),
        LivePipelineConfig(safe_live=True, allow_network=True, enabled_modules=("unknown",)),
        target="example.com",
        metadata=make_metadata(),
    )

    assert result["status"] == "rejected"
    assert result["module_results"] == []


def test_pipeline_does_not_call_external_scanner() -> None:
    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["audit_log"]["commands_executed"] == []
    assert all("tool:" not in str(event) for event in result["audit_events"])


def test_pipeline_does_not_use_subprocess(monkeypatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no process runner")))

    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["audit_log"]["commands_executed"] == []


def test_pipeline_does_not_use_os_system(monkeypatch) -> None:
    monkeypatch.setattr(os, "system", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no command runner")))

    result = run_safe_live_pipeline(make_approved_project(), LivePipelineConfig(safe_live=True, allow_network=True), target="example.com", metadata=make_metadata())

    assert result["audit_log"]["commands_executed"] == []


def test_pipeline_source_does_not_use_eval() -> None:
    source = inspect.getsource(__import__("core.live_pipeline").live_pipeline)

    assert "eval(" not in source


def test_pipeline_source_does_not_use_exec() -> None:
    source = inspect.getsource(__import__("core.live_pipeline").live_pipeline)

    assert "exec(" not in source


def test_pipeline_source_does_not_use_pickle() -> None:
    source = inspect.getsource(__import__("core.live_pipeline").live_pipeline)

    assert "pickle" not in source


def test_unit_test_does_not_perform_real_network_request(monkeypatch) -> None:
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no real network")))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no real DNS")))

    result = run_safe_live_pipeline(
        make_approved_project(),
        LivePipelineConfig(safe_live=True, allow_network=True),
        target="example.com",
        metadata=make_metadata(),
    )

    assert result["status"] in {"success", "partial_success"}
