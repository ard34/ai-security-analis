from __future__ import annotations

import importlib
import os
import socket
import subprocess

from cli import build_parser, format_history_rows, format_scan_summary, run_cli
from storage.json_io import export_scan_result_to_json


def make_scan_result(scan_id: str = "scan-cli-001") -> dict:
    return {
        "scan_id": scan_id,
        "target": "example.com",
        "normalized_target": "example.com",
        "scan_mode": "safe",
        "allowed_scope": {"domains": ["example.com"], "ips": []},
        "assets": ["https://example.com"],
        "endpoints": ["/"],
        "findings": [],
        "audit_log": {
            "scan_id": scan_id,
            "target": "example.com",
            "scan_mode": "safe",
            "modules_enabled": ["security_headers"],
            "commands_executed": [],
            "errors": [],
            "findings_generated": 0,
        },
        "started_at": "2026-01-01T00:00:00Z",
        "ended_at": "2026-01-01T00:00:01Z",
        "status": "success",
    }


def db_arg(tmp_path) -> list[str]:
    return ["--db-path", str(tmp_path / "test.sqlite3")]


def test_build_parser_can_be_created() -> None:
    assert build_parser().prog


def test_scan_command_runs_dummy_pipeline(tmp_path, capsys) -> None:
    code = run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Scan ID:" in out


def test_scan_command_requires_target(tmp_path) -> None:
    code = run_cli(["scan", "--allowed-domain", "example.com", *db_arg(tmp_path)])
    assert code != 0


def test_scan_command_requires_allowed_domain(tmp_path) -> None:
    code = run_cli(["scan", "--target", "example.com", *db_arg(tmp_path)])
    assert code != 0


def test_scan_valid_target_returns_zero(tmp_path) -> None:
    assert run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path)]) == 0


def test_scan_out_of_scope_returns_zero_with_rejected_status(tmp_path, capsys) -> None:
    code = run_cli(["scan", "--target", "evil.com", "--allowed-domain", "example.com", *db_arg(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Status: rejected" in out


def test_scan_save_stores_result(tmp_path) -> None:
    db_path = tmp_path / "test.sqlite3"
    code = run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", "--db-path", str(db_path), "--save"])
    assert code == 0
    assert db_path.exists()


def test_scan_json_output_creates_file(tmp_path) -> None:
    output = tmp_path / "scan.json"
    code = run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--json-output", str(output)])
    assert code == 0
    assert output.exists()


def test_scan_html_output_creates_file(tmp_path) -> None:
    output = tmp_path / "scan.html"
    code = run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--html-output", str(output)])
    assert code == 0
    assert output.exists()


def test_scan_pdf_output_creates_file(tmp_path) -> None:
    output = tmp_path / "scan.pdf"
    code = run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--pdf-output", str(output)])
    assert code == 0
    assert output.exists()
    assert output.read_bytes().startswith(b"%PDF")


def test_history_displays_saved_scan(tmp_path, capsys) -> None:
    run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--save"])
    code = run_cli(["history", *db_arg(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "example.com" in out


def test_history_empty_message(tmp_path, capsys) -> None:
    code = run_cli(["history", *db_arg(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "No scan history found." in out


def test_show_displays_scan_summary(tmp_path, capsys) -> None:
    run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--save"])
    code = run_cli(["show", "--scan-id", "scan-missing", *db_arg(tmp_path)])
    assert code != 0
    run_cli(["history", *db_arg(tmp_path)])
    # use known scan_id from repository via full output from one saved scan by exporting list is not needed here
    from storage.repositories import ScanResultRepository

    scan_id = ScanResultRepository(tmp_path / "test.sqlite3").list_scan_results()[0]["scan_id"]
    code = run_cli(["show", "--scan-id", scan_id, *db_arg(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Scan ID:" in out
    assert "Assets:" in out


def test_show_full_prints_json(tmp_path, capsys) -> None:
    run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--save"])
    from storage.repositories import ScanResultRepository

    scan_id = ScanResultRepository(tmp_path / "test.sqlite3").list_scan_results()[0]["scan_id"]
    code = run_cli(["show", "--scan-id", scan_id, "--full", *db_arg(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert '"scan_id"' in out


def test_show_missing_scan_returns_nonzero(tmp_path) -> None:
    assert run_cli(["show", "--scan-id", "missing", *db_arg(tmp_path)]) != 0


def save_one_scan(tmp_path) -> str:
    run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--save"])
    from storage.repositories import ScanResultRepository

    return ScanResultRepository(tmp_path / "test.sqlite3").list_scan_results()[0]["scan_id"]


def test_export_html_creates_file_from_history(tmp_path) -> None:
    scan_id = save_one_scan(tmp_path)
    output = tmp_path / "report.html"
    assert run_cli(["export-html", "--scan-id", scan_id, "--output", str(output), *db_arg(tmp_path)]) == 0
    assert output.exists()


def test_export_pdf_creates_file_from_history(tmp_path) -> None:
    scan_id = save_one_scan(tmp_path)
    output = tmp_path / "report.pdf"
    assert run_cli(["export-pdf", "--scan-id", scan_id, "--output", str(output), *db_arg(tmp_path)]) == 0
    assert output.read_bytes().startswith(b"%PDF")


def test_export_json_creates_file_from_history(tmp_path) -> None:
    scan_id = save_one_scan(tmp_path)
    output = tmp_path / "scan.json"
    assert run_cli(["export-json", "--scan-id", scan_id, "--output", str(output), *db_arg(tmp_path)]) == 0
    assert output.exists()


def test_import_json_reads_valid_file(tmp_path, capsys) -> None:
    input_path = tmp_path / "scan.json"
    export_scan_result_to_json(make_scan_result(), input_path)
    code = run_cli(["import-json", "--input", str(input_path), *db_arg(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Scan ID: scan-cli-001" in out


def test_import_json_save_stores_to_sqlite(tmp_path) -> None:
    input_path = tmp_path / "scan.json"
    export_scan_result_to_json(make_scan_result(), input_path)
    code = run_cli(["import-json", "--input", str(input_path), *db_arg(tmp_path), "--save"])
    assert code == 0
    from storage.repositories import ScanResultRepository

    assert ScanResultRepository(tmp_path / "test.sqlite3").count_scan_results() == 1


def test_import_json_rejects_invalid_json(tmp_path) -> None:
    input_path = tmp_path / "bad.json"
    input_path.write_text("{bad json", encoding="utf-8")
    assert run_cli(["import-json", "--input", str(input_path), *db_arg(tmp_path)]) != 0


def test_cli_does_not_use_network(monkeypatch, tmp_path) -> None:
    def fail_socket(*_args, **_kwargs):
        raise AssertionError("Network access is not allowed in CLI")

    monkeypatch.setattr(socket, "socket", fail_socket)
    assert run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--save"]) == 0


def test_cli_does_not_use_subprocess(monkeypatch, tmp_path) -> None:
    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess is not allowed in CLI")

    monkeypatch.setattr(subprocess, "run", fail_run)
    assert run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--save"]) == 0


def test_cli_does_not_use_os_system(monkeypatch, tmp_path) -> None:
    def fail_system(*_args, **_kwargs):
        raise AssertionError("os.system is not allowed in CLI")

    monkeypatch.setattr(os, "system", fail_system)
    assert run_cli(["scan", "--target", "example.com", "--allowed-domain", "example.com", *db_arg(tmp_path), "--save"]) == 0


def test_cli_module_import_safe() -> None:
    module = importlib.import_module("cli")
    assert hasattr(module, "run_cli")


def test_format_scan_summary_includes_required_fields() -> None:
    summary = format_scan_summary(make_scan_result())
    assert "Scan ID:" in summary
    assert "Target:" in summary
    assert "Status:" in summary
    assert "Scan mode:" in summary
    assert "Findings:" in summary
    assert "Commands executed:" in summary


def test_format_history_rows_empty_message() -> None:
    assert format_history_rows([]) == "No scan history found."

