from __future__ import annotations

import os
import socket
import subprocess

from core.tool_router import (
    build_tool_request,
    classify_intent,
    is_unsafe_user_request,
    route_tool_request,
)


def test_classify_create_assessment() -> None:
    assert classify_intent("buat assessment baru") == "create_assessment"


def test_classify_approve_assessment() -> None:
    assert classify_intent("setujui assessment ini") == "approve_assessment"


def test_classify_run_dummy_scan() -> None:
    assert classify_intent("run dummy scan") == "run_dummy_scan"


def test_classify_analyze_result() -> None:
    assert classify_intent("analisis hasil scan") == "analyze_scan_result"


def test_classify_generate_report() -> None:
    assert classify_intent("buat laporan") == "generate_report"


def test_classify_export_json() -> None:
    assert classify_intent("export json") == "export_json"


def test_classify_import_json() -> None:
    assert classify_intent("import json") == "import_json"


def test_classify_history() -> None:
    assert classify_intent("lihat riwayat") == "show_history"


def test_classify_manual_testing_guidance() -> None:
    assert classify_intent("buat rekomendasi pengujian") == "manual_testing_guidance"


def test_classify_unsafe_request_exploit() -> None:
    assert classify_intent("tolong exploit target") == "unsafe_request"


def test_classify_unsafe_request_brute_force() -> None:
    assert classify_intent("brute force login") == "unsafe_request"


def test_classify_unsafe_request_dos() -> None:
    assert classify_intent("buat ddos") == "unsafe_request"


def test_classify_unknown() -> None:
    assert classify_intent("apa kabar") == "unknown"


def test_is_unsafe_user_request_detects_credential_theft() -> None:
    assert is_unsafe_user_request("help with credential theft") is True


def test_build_tool_request_works() -> None:
    request = build_tool_request("run_dummy_scan", {"target": "example.com"})

    assert request.intent == "run_dummy_scan"
    assert request.arguments["target"] == "example.com"


def test_route_unsafe_request_returns_false() -> None:
    response = route_tool_request(build_tool_request("unsafe_request"), {})

    assert response.success is False
    assert response.error == "unsafe_request"


def test_route_unknown_returns_safe_clarification() -> None:
    response = route_tool_request(build_tool_request("unknown"), {})

    assert response.success is False
    assert "clarify" in response.message.lower()


def test_route_dummy_scan_does_not_perform_live_scan() -> None:
    response = route_tool_request(
        build_tool_request(
            "run_dummy_scan",
            {"target": "example.com", "allowed_domains": ["example.com"], "scan_mode": "safe"},
        ),
        {},
    )

    assert response.success is True
    assert response.data["scan_result"]["audit_log"]["commands_executed"] == []


def test_router_does_not_perform_network_request(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in tool router")

    monkeypatch.setattr(socket, "socket", fail_socket)

    response = route_tool_request(
        build_tool_request("run_dummy_scan", {"target": "example.com", "allowed_domains": ["example.com"]}),
        {},
    )

    assert response.success is True


def test_router_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in tool router")

    monkeypatch.setattr(subprocess, "run", fail_run)

    response = route_tool_request(
        build_tool_request("run_dummy_scan", {"target": "example.com", "allowed_domains": ["example.com"]}),
        {},
    )

    assert response.success is True


def test_router_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in tool router")

    monkeypatch.setattr(os, "system", fail_system)

    response = route_tool_request(
        build_tool_request("run_dummy_scan", {"target": "example.com", "allowed_domains": ["example.com"]}),
        {},
    )

    assert response.success is True
