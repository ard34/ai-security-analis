from __future__ import annotations

import socket

from reporting.html_report import generate_html_report, save_html_report


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
            },
            {
                "target": "example.com",
                "asset": "https://example.com",
                "endpoint": "/",
                "module": "security_headers",
                "finding_type": "missing_header",
                "title": "Missing Cross-Origin-Opener-Policy Header",
                "severity": "info",
                "confidence": "low",
                "evidence": "Cross-Origin-Opener-Policy header not present",
                "recommendation": "Set Cross-Origin-Opener-Policy where compatible.",
                "source": "headers_module",
                "is_potential": True,
            },
        ],
        "audit_log": {
            "scan_id": "scan-123",
            "target": "example.com",
            "scan_mode": "safe",
            "modules_enabled": ["security_headers"],
            "commands_executed": [],
            "errors": [],
            "findings_generated": 2,
        },
        "started_at": "2026-05-29T10:00:00+00:00",
        "ended_at": "2026-05-29T10:00:01+00:00",
        "status": "success",
    }


def test_generate_html_report_returns_string() -> None:
    assert isinstance(generate_html_report(make_scan_result()), str)


def test_html_contains_project_name() -> None:
    assert "AI Security Analyst" in generate_html_report(make_scan_result())


def test_html_contains_report_title() -> None:
    assert "Security Reconnaissance Report" in generate_html_report(make_scan_result())


def test_html_contains_target() -> None:
    assert "example.com" in generate_html_report(make_scan_result())


def test_html_contains_scan_mode() -> None:
    assert "safe" in generate_html_report(make_scan_result())


def test_html_contains_status() -> None:
    assert "success" in generate_html_report(make_scan_result())


def test_html_contains_authorized_scope() -> None:
    html = generate_html_report(make_scan_result())
    assert "Authorized Scope" in html
    assert "Allowed domains" in html


def test_html_contains_executive_summary() -> None:
    assert "Executive Summary" in generate_html_report(make_scan_result())


def test_html_contains_attack_surface_summary() -> None:
    assert "Attack Surface Summary" in generate_html_report(make_scan_result())


def test_html_contains_findings_table_when_findings_exist() -> None:
    html = generate_html_report(make_scan_result())
    assert "findings-table" in html
    assert "Missing Content-Security-Policy Header" in html


def test_html_shows_empty_findings_state() -> None:
    result = make_scan_result()
    result["findings"] = []
    assert "No findings recorded." in generate_html_report(result)


def test_severity_summary_counts_expected_values() -> None:
    html = generate_html_report(make_scan_result())
    assert "<td>info</td><td>1</td>" in html
    assert "<td>low</td><td>1</td>" in html
    assert "<td>medium</td><td>0</td>" in html
    assert "<td>high</td><td>0</td>" in html
    assert "<td>critical</td><td>0</td>" in html


def test_confidence_summary_counts_expected_values() -> None:
    html = generate_html_report(make_scan_result())
    assert "<td>low</td><td>1</td>" in html
    assert "<td>medium</td><td>1</td>" in html
    assert "<td>high</td><td>0</td>" in html


def test_audit_log_is_rendered() -> None:
    html = generate_html_report(make_scan_result())
    assert "Audit Log" in html
    assert "security_headers" in html


def test_empty_commands_render_no_external_commands_message() -> None:
    assert "No external commands executed." in generate_html_report(make_scan_result())


def test_safety_disclaimer_is_rendered() -> None:
    html = generate_html_report(make_scan_result())
    assert "authorized security assessment only" in html
    assert "All findings are potential findings" in html


def test_html_escaping_blocks_script_injection() -> None:
    result = make_scan_result()
    result["target"] = "<script>alert(1)</script>"
    result["findings"][0]["title"] = "<script>alert(1)</script>"
    html = generate_html_report(result)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_report_generator_does_not_use_network(monkeypatch) -> None:
    def fail_socket(*_args, **_kwargs):
        raise AssertionError("Network access is not allowed in report generator")

    monkeypatch.setattr(socket, "socket", fail_socket)

    assert "AI Security Analyst" in generate_html_report(make_scan_result())


def test_save_html_report_creates_html_file(tmp_path) -> None:
    output = tmp_path / "report.html"
    path = save_html_report(make_scan_result(), str(output))

    assert output.exists()
    assert output.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert path == str(output)


def test_save_html_report_returns_output_path(tmp_path) -> None:
    output = tmp_path / "report.html"
    assert save_html_report(make_scan_result(), str(output)) == str(output)


def test_rejected_result_can_be_reported() -> None:
    result = make_scan_result()
    result["status"] = "rejected"
    result["findings"] = []

    html = generate_html_report(result)

    assert "rejected" in html
    assert "No findings recorded." in html


def test_empty_assets_state_is_rendered() -> None:
    result = make_scan_result()
    result["assets"] = []
    assert "No assets recorded." in generate_html_report(result)


def test_empty_endpoints_state_is_rendered() -> None:
    result = make_scan_result()
    result["endpoints"] = []
    assert "No endpoints recorded." in generate_html_report(result)

