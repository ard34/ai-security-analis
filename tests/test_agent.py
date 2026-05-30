from __future__ import annotations

import os
import socket
import subprocess

from core.agent import analyze_user_request, generate_manual_testing_guidance, summarize_agent_capabilities
from core.assessment import approve_assessment_project, create_assessment_project


def make_project(approved: bool = False):
    project = create_assessment_project(
        name="Preprod API Assessment",
        owner="Security Team",
        operator="Internal Pentester",
        authorization_note="Approved ticket RT-001 for pre-production assessment.",
        allowed_domains=["example.com"],
        environment="staging",
        scan_mode="safe",
    )
    return approve_assessment_project(project) if approved else project


def make_finding() -> dict:
    return {
        "module": "security_headers",
        "title": "Missing Content-Security-Policy Header",
        "severity": "low",
        "confidence": "medium",
        "evidence": "Content-Security-Policy header not present.",
        "is_potential": True,
    }


def test_empty_user_message_returns_safe_error() -> None:
    response = analyze_user_request("")

    assert response.success is False
    assert response.message


def test_unsafe_exploit_request_refused() -> None:
    response = analyze_user_request("exploit this target")

    assert response.success is False
    assert response.intent == "unsafe_request"


def test_unsafe_brute_force_request_refused() -> None:
    response = analyze_user_request("brute force login")

    assert response.success is False
    assert response.refusal_reason


def test_unsafe_dos_request_refused() -> None:
    response = analyze_user_request("ddos this app")

    assert response.success is False
    assert response.refusal_reason


def test_unknown_request_returns_clarification() -> None:
    response = analyze_user_request("halo")

    assert response.success is False
    assert response.intent == "unknown"


def test_agent_can_summarize_capabilities() -> None:
    summary = summarize_agent_capabilities()

    assert "dummy scan" in summary
    assert "reject unsafe" in summary


def test_agent_detects_run_dummy_scan_intent() -> None:
    response = analyze_user_request("run dummy scan", project=make_project(approved=True))

    assert response.intent == "run_dummy_scan"


def test_run_dummy_scan_requires_assessment_project() -> None:
    response = analyze_user_request("run dummy scan")

    assert response.success is False
    assert "assessment project" in response.message


def test_run_dummy_scan_requires_approved_assessment() -> None:
    response = analyze_user_request("run dummy scan", project=make_project())

    assert response.success is False
    assert "approved" in response.message


def test_run_dummy_scan_works_with_approved_assessment() -> None:
    response = analyze_user_request("run dummy scan", project=make_project(approved=True))

    assert response.success is True
    assert response.data["scan_result"]["status"] == "success"


def test_manual_testing_guidance_returns_list() -> None:
    guidance = generate_manual_testing_guidance([make_finding()])

    assert isinstance(guidance, list)
    assert guidance


def test_manual_testing_guidance_marks_validation_status() -> None:
    guidance = generate_manual_testing_guidance([make_finding()])

    assert guidance[0]["validation_status"] == "needs_manual_validation"


def test_manual_testing_guidance_does_not_include_exploit_payload() -> None:
    guidance = generate_manual_testing_guidance([make_finding()])

    assert "payload" not in str(guidance).lower()
    assert "exploit" not in str(guidance).lower()


def test_generate_report_intent_is_handled_safely() -> None:
    response = analyze_user_request("buat report")

    assert response.success is True
    assert response.intent == "generate_report"


def test_agent_response_contains_intent() -> None:
    assert analyze_user_request("buat report").intent


def test_agent_response_contains_message() -> None:
    assert analyze_user_request("buat report").message


def test_agent_does_not_use_network(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in agent orchestrator")

    monkeypatch.setattr(socket, "socket", fail_socket)

    response = analyze_user_request("apa kemampuan kamu?")

    assert response.message


def test_agent_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in agent orchestrator")

    monkeypatch.setattr(subprocess, "run", fail_run)

    response = analyze_user_request("buat rekomendasi manual testing")

    assert response.message


def test_agent_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in agent orchestrator")

    monkeypatch.setattr(os, "system", fail_system)

    response = analyze_user_request("show capabilities")

    assert response.message


def test_agent_does_not_call_external_llm_api(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("External LLM API calls are disabled")

    monkeypatch.setattr(socket, "socket", fail_socket)

    response = analyze_user_request("buat rekomendasi manual testing", context={"findings": [make_finding()]})

    assert response.success is True
