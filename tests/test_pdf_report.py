from __future__ import annotations

from copy import deepcopy
import os
import socket
import subprocess

import pytest

from reporting.pdf_report import ensure_parent_directory, generate_pdf_report, validate_pdf_output_path


def make_scan_result() -> dict:
    return {
        "scan_id": "scan-123",
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
            "scan_id": "scan-123",
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


def test_generate_pdf_report_creates_pdf_file(tmp_path) -> None:
    output_path = tmp_path / "report.pdf"
    result_path = generate_pdf_report(make_scan_result(), str(output_path))
    assert result_path == str(output_path)
    assert output_path.exists()


def test_generate_pdf_report_returns_output_path(tmp_path) -> None:
    output_path = tmp_path / "report.pdf"
    assert generate_pdf_report(make_scan_result(), str(output_path)) == str(output_path)


def test_output_path_must_be_pdf() -> None:
    with pytest.raises(ValueError):
        validate_pdf_output_path("report.html")


def test_non_pdf_extension_rejected(tmp_path) -> None:
    with pytest.raises(ValueError):
        generate_pdf_report(make_scan_result(), str(tmp_path / "report.txt"))


def test_parent_directory_created_automatically(tmp_path) -> None:
    output_path = tmp_path / "nested" / "reports" / "report.pdf"
    generate_pdf_report(make_scan_result(), str(output_path))
    assert output_path.parent.exists()


def test_pdf_not_empty(tmp_path) -> None:
    output_path = tmp_path / "report.pdf"
    generate_pdf_report(make_scan_result(), str(output_path))
    assert output_path.stat().st_size > 0


def test_pdf_has_magic_header(tmp_path) -> None:
    output_path = tmp_path / "report.pdf"
    generate_pdf_report(make_scan_result(), str(output_path))
    assert output_path.read_bytes().startswith(b"%PDF")


def test_pdf_can_be_created_from_success_result(tmp_path) -> None:
    output_path = tmp_path / "success.pdf"
    generate_pdf_report(make_scan_result(), str(output_path))
    assert output_path.exists()


def test_pdf_can_be_created_from_rejected_result(tmp_path) -> None:
    result = make_scan_result()
    result["status"] = "rejected"
    result["findings"] = []
    output_path = tmp_path / "rejected.pdf"
    generate_pdf_report(result, str(output_path))
    assert output_path.exists()


def test_pdf_can_be_created_without_findings(tmp_path) -> None:
    result = make_scan_result()
    result["findings"] = []
    output_path = tmp_path / "empty-findings.pdf"
    generate_pdf_report(result, str(output_path))
    assert output_path.exists()


def test_pdf_report_does_not_use_network(monkeypatch, tmp_path) -> None:
    def fail_socket(*_args, **_kwargs):
        raise AssertionError("Network access is not allowed in PDF generator")

    monkeypatch.setattr(socket, "socket", fail_socket)
    output_path = tmp_path / "report.pdf"
    generate_pdf_report(make_scan_result(), str(output_path))
    assert output_path.exists()


def test_pdf_report_does_not_use_subprocess(monkeypatch, tmp_path) -> None:
    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess is not allowed in PDF generator")

    monkeypatch.setattr(subprocess, "run", fail_run)
    output_path = tmp_path / "report.pdf"
    generate_pdf_report(make_scan_result(), str(output_path))
    assert output_path.exists()


def test_pdf_report_does_not_use_os_system(monkeypatch, tmp_path) -> None:
    def fail_system(*_args, **_kwargs):
        raise AssertionError("os.system is not allowed in PDF generator")

    monkeypatch.setattr(os, "system", fail_system)
    output_path = tmp_path / "report.pdf"
    generate_pdf_report(make_scan_result(), str(output_path))
    assert output_path.exists()


def test_generate_pdf_report_does_not_mutate_input(tmp_path) -> None:
    result = make_scan_result()
    original = deepcopy(result)
    generate_pdf_report(result, str(tmp_path / "report.pdf"))
    assert result == original


def test_malicious_escaped_input_still_generates_pdf(tmp_path) -> None:
    result = make_scan_result()
    result["target"] = "<script>alert(1)</script>"
    result["findings"][0]["title"] = "<script>alert(1)</script>"
    output_path = tmp_path / "malicious.pdf"
    generate_pdf_report(result, str(output_path))
    assert output_path.exists()
    assert output_path.read_bytes().startswith(b"%PDF")


def test_validate_pdf_output_path_accepts_pdf() -> None:
    assert validate_pdf_output_path("report.pdf") == "report.pdf"


def test_ensure_parent_directory_creates_directory(tmp_path) -> None:
    output_path = tmp_path / "nested" / "report.pdf"
    ensure_parent_directory(str(output_path))
    assert output_path.parent.exists()

