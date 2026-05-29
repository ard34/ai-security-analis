from __future__ import annotations

import importlib
import os
import socket
import subprocess

from ui.app import (
    build_report_filename,
    can_export_report,
    generate_html_report_bytes,
    generate_pdf_report_bytes,
)


def make_scan_result(scan_id: str = "scan-123") -> dict:
    return {
        "scan_id": scan_id,
        "target": "example.com",
        "normalized_target": "example.com",
        "scan_mode": "safe",
        "allowed_scope": {"domains": ["example.com"], "ips": []},
        "assets": [{"url": "https://example.com"}],
        "endpoints": [{"url": "https://example.com/", "path": "/"}],
        "findings": [
            {
                "target": "example.com",
                "asset": "https://example.com",
                "endpoint": "/",
                "module": "security_headers",
                "finding_type": "missing_header",
                "title": "Missing Content-Security-Policy Header",
                "severity": "low",
                "confidence": "medium",
                "evidence": "Content-Security-Policy header not present",
                "recommendation": "Implement a restrictive Content-Security-Policy header.",
                "source": "headers_module",
                "is_potential": True,
            }
        ],
        "audit_log": {
            "scan_id": scan_id,
            "target": "example.com",
            "scan_mode": "safe",
            "modules_enabled": ["security_headers"],
            "commands_executed": [],
            "errors": [],
            "findings_generated": 1,
        },
        "started_at": "2026-05-29T10:00:00+00:00",
        "ended_at": "2026-05-29T10:00:01+00:00",
        "status": "success",
    }


def test_build_report_filename_html() -> None:
    assert build_report_filename(make_scan_result(), "html") == "ai-security-analyst-report-scan-123.html"


def test_build_report_filename_pdf() -> None:
    assert build_report_filename(make_scan_result(), "pdf") == "ai-security-analyst-report-scan-123.pdf"


def test_build_report_filename_sanitizes_scan_id() -> None:
    result = make_scan_result("../bad/<script>")
    assert build_report_filename(result, "html") == "ai-security-analyst-report-bad-script.html"


def test_build_report_filename_uses_unknown_for_empty_scan_id() -> None:
    assert build_report_filename(make_scan_result(""), "pdf") == "ai-security-analyst-report-unknown.pdf"


def test_can_export_report_none_false() -> None:
    assert can_export_report(None) is False


def test_can_export_report_empty_false() -> None:
    assert can_export_report({}) is False


def test_can_export_report_valid_true() -> None:
    assert can_export_report(make_scan_result()) is True


def test_generate_html_report_bytes_returns_bytes() -> None:
    assert isinstance(generate_html_report_bytes(make_scan_result()), bytes)


def test_generate_html_report_bytes_contains_project_name() -> None:
    assert b"AI Security Analyst" in generate_html_report_bytes(make_scan_result())


def test_generate_pdf_report_bytes_returns_bytes() -> None:
    assert isinstance(generate_pdf_report_bytes(make_scan_result()), bytes)


def test_generate_pdf_report_bytes_starts_with_pdf_magic() -> None:
    assert generate_pdf_report_bytes(make_scan_result()).startswith(b"%PDF")


def test_report_export_helpers_do_not_use_network(monkeypatch) -> None:
    def fail_socket(*_args, **_kwargs):
        raise AssertionError("Network access is not allowed in dashboard report export helpers")

    monkeypatch.setattr(socket, "socket", fail_socket)
    html_bytes = generate_html_report_bytes(make_scan_result())
    assert b"AI Security Analyst" in html_bytes


def test_pdf_export_helper_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess is not allowed in dashboard report export helpers")

    monkeypatch.setattr(subprocess, "run", fail_run)
    assert generate_pdf_report_bytes(make_scan_result()).startswith(b"%PDF")


def test_pdf_export_helper_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*_args, **_kwargs):
        raise AssertionError("os.system is not allowed in dashboard report export helpers")

    monkeypatch.setattr(os, "system", fail_system)
    assert generate_pdf_report_bytes(make_scan_result()).startswith(b"%PDF")


def test_ui_app_import_safe_without_streamlit_runtime() -> None:
    module = importlib.import_module("ui.app")
    assert hasattr(module, "main")
    assert hasattr(module, "generate_pdf_report_bytes")

