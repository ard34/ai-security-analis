from __future__ import annotations

import importlib
import socket

from core.models import Finding
from ui.app import findings_to_table_rows, parse_comma_separated_values, summarize_pipeline_result


def test_parse_comma_separated_values_trims_whitespace() -> None:
    assert parse_comma_separated_values(" example.com, app.example.com ") == ["example.com", "app.example.com"]


def test_parse_comma_separated_values_removes_empty_items() -> None:
    assert parse_comma_separated_values("example.com, , ,api.example.com,") == ["example.com", "api.example.com"]


def test_summarize_pipeline_result_counts_assets() -> None:
    result = {"assets": [{"url": "https://example.com"}], "audit_log": {}}
    assert summarize_pipeline_result(result)["assets"] == 1


def test_summarize_pipeline_result_counts_endpoints() -> None:
    result = {"endpoints": [{"url": "https://example.com/"}], "audit_log": {}}
    assert summarize_pipeline_result(result)["endpoints"] == 1


def test_summarize_pipeline_result_counts_findings() -> None:
    result = {"findings": [{"title": "Potential finding"}], "audit_log": {}}
    assert summarize_pipeline_result(result)["findings"] == 1


def test_summarize_pipeline_result_counts_commands_executed() -> None:
    result = {"audit_log": {"commands_executed": [["dummy"]]}}
    assert summarize_pipeline_result(result)["commands_executed"] == 1


def test_findings_to_table_rows_returns_list_of_dicts() -> None:
    finding = Finding(
        target="example.com",
        asset="https://example.com",
        endpoint="/",
        module="security_headers",
        finding_type="missing_header",
        title="Missing Header",
        severity="low",
        confidence="medium",
        evidence="Header not present",
        recommendation="Set the header",
        source="headers_module",
    )

    rows = findings_to_table_rows([finding])

    assert isinstance(rows, list)
    assert rows[0]["title"] == "Missing Header"
    assert rows[0]["is_potential"] is True


def test_dashboard_helpers_do_not_use_network(monkeypatch) -> None:
    def fail_socket(*_args, **_kwargs):
        raise AssertionError("Network access is not allowed in dashboard helpers")

    monkeypatch.setattr(socket, "socket", fail_socket)

    values = parse_comma_separated_values("example.com")
    summary = summarize_pipeline_result({"assets": [], "endpoints": [], "findings": [], "audit_log": {"commands_executed": []}})
    rows = findings_to_table_rows([])

    assert values == ["example.com"]
    assert summary["commands_executed"] == 0
    assert rows == []


def test_ui_app_import_safe_without_streamlit_runtime() -> None:
    module = importlib.import_module("ui.app")
    assert hasattr(module, "main")
    assert hasattr(module, "parse_comma_separated_values")

