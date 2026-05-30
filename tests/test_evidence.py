from __future__ import annotations

import inspect
import os
import socket
import subprocess

import pytest

import core.evidence as evidence_module
from core.evidence import (
    EvidenceItem,
    collect_evidence_from_scan_result,
    create_evidence_id,
    create_evidence_item,
    evidence_from_finding,
    evidence_item_from_dict,
    evidence_item_to_dict,
    filter_evidence,
    sanitize_evidence_data,
    summarize_evidence,
)


def make_data() -> dict:
    return {"header": "Content-Security-Policy", "status": "missing"}


def make_finding() -> dict:
    return {
        "target": "example.com",
        "asset": "https://example.com",
        "endpoint": "/",
        "module": "security_headers",
        "finding_type": "missing_header",
        "title": "Missing CSP",
        "severity": "low",
        "confidence": "medium",
        "evidence": "CSP header missing",
        "recommendation": "Add CSP",
        "source": "headers_module",
        "is_potential": True,
    }


def test_create_evidence_item_valid() -> None:
    item = create_evidence_item("example.com", "headers_module", "http_header", "Missing CSP", make_data())

    assert isinstance(item, EvidenceItem)
    assert item.evidence_id.startswith("ev_")


def test_evidence_id_deterministic() -> None:
    first = create_evidence_id("example.com", "headers_module", "http_header", "Missing CSP", make_data())
    second = create_evidence_id("example.com", "headers_module", "http_header", "Missing CSP", make_data())

    assert first == second


def test_evidence_id_changes_when_data_changes() -> None:
    first = create_evidence_id("example.com", "headers_module", "http_header", "Missing CSP", make_data())
    second = create_evidence_id("example.com", "headers_module", "http_header", "Missing CSP", {"status": "present"})

    assert first != second


def test_invalid_evidence_type_rejected() -> None:
    with pytest.raises(ValueError):
        create_evidence_item("example.com", "source", "bad", "Title", {})


def test_empty_target_rejected() -> None:
    with pytest.raises(ValueError):
        create_evidence_item("", "source", "manual_note", "Title", {})


def test_empty_source_rejected() -> None:
    with pytest.raises(ValueError):
        create_evidence_item("example.com", "", "manual_note", "Title", {})


def test_empty_title_rejected() -> None:
    with pytest.raises(ValueError):
        create_evidence_item("example.com", "source", "manual_note", "", {})


def test_sensitive_password_redacted() -> None:
    assert sanitize_evidence_data({"password": "secret"})["password"] == "[REDACTED]"


def test_sensitive_token_redacted() -> None:
    assert sanitize_evidence_data({"token": "abc"})["token"] == "[REDACTED]"


def test_sensitive_authorization_redacted_case_insensitive() -> None:
    assert sanitize_evidence_data({"Authorization": "Bearer abc"})["Authorization"] == "[REDACTED]"


def test_nested_sensitive_data_redacted() -> None:
    assert sanitize_evidence_data({"nested": {"api_key": "abc"}})["nested"]["api_key"] == "[REDACTED]"


def test_original_data_not_mutated() -> None:
    data = {"nested": {"token": "abc"}}

    sanitize_evidence_data(data)

    assert data["nested"]["token"] == "abc"


def test_evidence_item_to_dict_returns_dict() -> None:
    item = create_evidence_item("example.com", "headers_module", "http_header", "Missing CSP", make_data())

    assert isinstance(evidence_item_to_dict(item), dict)


def test_evidence_item_from_dict_roundtrip() -> None:
    item = create_evidence_item("example.com", "headers_module", "http_header", "Missing CSP", make_data())

    restored = evidence_item_from_dict(evidence_item_to_dict(item))

    assert restored == item


def test_evidence_from_finding_creates_item() -> None:
    item = evidence_from_finding(make_finding(), scan_id="scan-001")

    assert item.evidence_type == "finding_evidence"
    assert item.data["module"] == "security_headers"


def test_collect_evidence_from_scan_result_gets_findings() -> None:
    items = collect_evidence_from_scan_result({"scan_id": "scan-001", "target": "example.com", "findings": [make_finding()]})

    assert any(item.evidence_type == "finding_evidence" for item in items)


def test_collect_evidence_from_scan_result_gets_assets() -> None:
    items = collect_evidence_from_scan_result({"target": "example.com", "assets": [{"url": "https://example.com"}]})

    assert any("asset" in item.tags for item in items)


def test_collect_evidence_from_scan_result_gets_endpoints() -> None:
    items = collect_evidence_from_scan_result({"target": "example.com", "endpoints": [{"path": "/"}]})

    assert any("endpoint" in item.tags for item in items)


def test_filter_evidence_by_target() -> None:
    items = [
        create_evidence_item("example.com", "manual", "manual_note", "A", {}),
        create_evidence_item("other.com", "manual", "manual_note", "B", {}),
    ]

    assert len(filter_evidence(items, target="example.com")) == 1


def test_filter_evidence_by_source() -> None:
    items = [create_evidence_item("example.com", "manual", "manual_note", "A", {})]

    assert filter_evidence(items, source="manual")


def test_filter_evidence_by_type() -> None:
    items = [create_evidence_item("example.com", "manual", "manual_note", "A", {})]

    assert filter_evidence(items, evidence_type="manual_note")


def test_filter_evidence_by_tag() -> None:
    items = [create_evidence_item("example.com", "manual", "manual_note", "A", {}, tags=["review"])]

    assert filter_evidence(items, tag="review")


def test_summarize_evidence_counts_total() -> None:
    items = [create_evidence_item("example.com", "manual", "manual_note", "A", {})]

    assert summarize_evidence(items)["total"] == 1


def test_summarize_evidence_counts_by_type() -> None:
    items = [create_evidence_item("example.com", "manual", "manual_note", "A", {})]

    assert summarize_evidence(items)["by_type"]["manual_note"] == 1


def test_evidence_does_not_use_network(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in evidence layer")

    monkeypatch.setattr(socket, "socket", fail_socket)

    item = create_evidence_item("example.com", "headers_module", "http_header", "Missing CSP", make_data())

    assert item.evidence_id


def test_evidence_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in evidence layer")

    monkeypatch.setattr(subprocess, "run", fail_run)

    item = create_evidence_item("example.com", "manual", "manual_note", "Manual note", {"note": "Needs review"})

    assert item.evidence_id


def test_evidence_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in evidence layer")

    monkeypatch.setattr(os, "system", fail_system)

    item = create_evidence_item("example.com", "manual", "manual_note", "Manual note", {"note": "Needs review"})

    assert item.evidence_id


def test_evidence_source_does_not_use_eval() -> None:
    assert "eval(" not in inspect.getsource(evidence_module)


def test_evidence_source_does_not_use_exec() -> None:
    assert "exec(" not in inspect.getsource(evidence_module)


def test_evidence_source_does_not_use_pickle() -> None:
    assert "pickle" not in inspect.getsource(evidence_module)
