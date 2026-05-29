from __future__ import annotations

from copy import deepcopy
import os
import pickle
import socket
import subprocess

import pytest

from reporting.html_report import generate_html_report
from reporting.pdf_report import generate_pdf_report
from storage.json_io import (
    export_scan_result_to_json,
    import_scan_result_from_json,
    scan_result_from_json_bytes,
    scan_result_to_json_bytes,
)
from storage.repositories import ScanResultRepository


def make_scan_result(scan_id: str = "scan-json-001", target: str = "example.com", status: str = "success") -> dict:
    return {
        "scan_id": scan_id,
        "target": target,
        "normalized_target": target,
        "scan_mode": "safe",
        "allowed_scope": {"domains": ["example.com"], "ips": []},
        "assets": [f"https://{target}"] if status == "success" else [],
        "endpoints": ["/"] if status == "success" else [],
        "findings": [
            {
                "target": target,
                "asset": f"https://{target}",
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
            "target": target,
            "scan_mode": "safe",
            "modules_enabled": ["security_headers"],
            "commands_executed": [],
            "errors": [],
            "findings_generated": 1,
        },
        "started_at": "2026-01-01T00:00:00Z",
        "ended_at": "2026-01-01T00:00:01Z",
        "status": status,
    }


def write_json(tmp_path, result: dict | None = None):
    path = tmp_path / "scan.json"
    export_scan_result_to_json(result or make_scan_result(), path)
    return path


def test_export_creates_json_file(tmp_path) -> None:
    path = write_json(tmp_path)
    assert path.exists()


def test_export_returns_output_path(tmp_path) -> None:
    path = tmp_path / "scan.json"
    assert export_scan_result_to_json(make_scan_result(), path) == str(path)


def test_export_writes_utf8_json(tmp_path) -> None:
    path = write_json(tmp_path)
    text = path.read_text(encoding="utf-8")
    assert '"scan_id": "scan-json-001"' in text


def test_export_rejects_non_json_path(tmp_path) -> None:
    with pytest.raises(ValueError):
        export_scan_result_to_json(make_scan_result(), tmp_path / "scan.txt")


def test_export_creates_parent_directory(tmp_path) -> None:
    path = tmp_path / "nested" / "scan.json"
    export_scan_result_to_json(make_scan_result(), path)
    assert path.parent.exists()


def test_export_does_not_mutate_input_dict(tmp_path) -> None:
    result = make_scan_result()
    original = deepcopy(result)
    export_scan_result_to_json(result, tmp_path / "scan.json")
    assert result == original


def test_import_reads_valid_scan_result(tmp_path) -> None:
    path = write_json(tmp_path)
    assert import_scan_result_from_json(path)["scan_id"] == "scan-json-001"


def test_import_rejects_non_json_path(tmp_path) -> None:
    path = tmp_path / "scan.txt"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        import_scan_result_from_json(path)


def test_import_rejects_missing_file(tmp_path) -> None:
    with pytest.raises(FileNotFoundError):
        import_scan_result_from_json(tmp_path / "missing.json")


def test_import_rejects_invalid_json(tmp_path) -> None:
    path = tmp_path / "scan.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        import_scan_result_from_json(path)


def test_import_rejects_missing_scan_id(tmp_path) -> None:
    result = make_scan_result()
    result.pop("scan_id")
    with pytest.raises(ValueError):
        scan_result_to_json_bytes(result)


def test_import_rejects_missing_target(tmp_path) -> None:
    result = make_scan_result()
    result.pop("target")
    with pytest.raises(ValueError):
        scan_result_to_json_bytes(result)


def test_import_rejects_invalid_scan_mode() -> None:
    result = make_scan_result()
    result["scan_mode"] = "aggressive"
    with pytest.raises(ValueError):
        scan_result_to_json_bytes(result)


def test_import_rejects_invalid_status() -> None:
    result = make_scan_result()
    result["status"] = "owned"
    with pytest.raises(ValueError):
        scan_result_to_json_bytes(result)


def test_import_rejects_findings_that_are_not_list() -> None:
    result = make_scan_result()
    result["findings"] = {}
    with pytest.raises(ValueError):
        scan_result_to_json_bytes(result)


def test_import_rejects_audit_log_that_is_not_dict() -> None:
    result = make_scan_result()
    result["audit_log"] = []
    with pytest.raises(ValueError):
        scan_result_to_json_bytes(result)


def test_import_rejects_invalid_severity() -> None:
    result = make_scan_result()
    result["findings"][0]["severity"] = "urgent"
    with pytest.raises(ValueError):
        scan_result_to_json_bytes(result)


def test_import_rejects_invalid_confidence() -> None:
    result = make_scan_result()
    result["findings"][0]["confidence"] = "certain"
    with pytest.raises(ValueError):
        scan_result_to_json_bytes(result)


def test_import_rejects_non_potential_finding() -> None:
    result = make_scan_result()
    result["findings"][0]["is_potential"] = False
    with pytest.raises(ValueError):
        scan_result_to_json_bytes(result)


def test_scan_result_to_json_bytes_returns_bytes() -> None:
    assert isinstance(scan_result_to_json_bytes(make_scan_result()), bytes)


def test_scan_result_from_json_bytes_returns_dict() -> None:
    assert scan_result_from_json_bytes(scan_result_to_json_bytes(make_scan_result()))["target"] == "example.com"


def test_bytes_helper_rejects_invalid_json_bytes() -> None:
    with pytest.raises(ValueError):
        scan_result_from_json_bytes(b"{bad json")


def test_json_io_does_not_use_pickle(monkeypatch, tmp_path) -> None:
    def fail_dumps(*_args, **_kwargs):
        raise AssertionError("pickle is not allowed in JSON IO")

    monkeypatch.setattr(pickle, "dumps", fail_dumps)
    write_json(tmp_path)


def test_json_io_does_not_use_network(monkeypatch, tmp_path) -> None:
    def fail_socket(*_args, **_kwargs):
        raise AssertionError("Network access is not allowed in JSON IO")

    monkeypatch.setattr(socket, "socket", fail_socket)
    path = write_json(tmp_path)
    assert import_scan_result_from_json(path)["scan_id"] == "scan-json-001"


def test_json_io_does_not_use_subprocess(monkeypatch, tmp_path) -> None:
    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess is not allowed in JSON IO")

    monkeypatch.setattr(subprocess, "run", fail_run)
    assert write_json(tmp_path).exists()


def test_json_io_does_not_use_os_system(monkeypatch, tmp_path) -> None:
    def fail_system(*_args, **_kwargs):
        raise AssertionError("os.system is not allowed in JSON IO")

    monkeypatch.setattr(os, "system", fail_system)
    assert write_json(tmp_path).exists()


def test_imported_scan_result_can_be_saved_to_repository(tmp_path) -> None:
    imported = import_scan_result_from_json(write_json(tmp_path))
    repository = ScanResultRepository(tmp_path / "history.sqlite3")
    repository.save_scan_result(imported)
    assert repository.count_scan_results() == 1


def test_imported_scan_result_can_generate_html_report(tmp_path) -> None:
    imported = import_scan_result_from_json(write_json(tmp_path))
    assert "AI Security Analyst" in generate_html_report(imported)


def test_imported_scan_result_can_generate_pdf_report(tmp_path) -> None:
    imported = import_scan_result_from_json(write_json(tmp_path))
    output_path = tmp_path / "report.pdf"
    generate_pdf_report(imported, str(output_path))
    assert output_path.read_bytes().startswith(b"%PDF")

