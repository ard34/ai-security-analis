from __future__ import annotations

import inspect
import os
import socket
import subprocess

import core.manual_testing as manual_testing_module
from core.manual_testing import (
    DEFAULT_SAFETY_NOTE,
    ManualTestRecommendation,
    contains_unsafe_testing_instruction,
    create_manual_test_recommendation,
    create_recommendation_id,
    generate_manual_testing_recommendations,
    infer_category_from_finding,
    infer_priority_from_finding,
    manual_test_recommendation_from_dict,
    manual_test_recommendation_to_dict,
    normalize_category,
    normalize_priority,
    normalize_validation_status,
    recommendation_from_finding,
    sanitize_manual_steps,
    summarize_manual_testing_recommendations,
)


def make_finding(**overrides) -> dict:
    finding = {
        "target": "example.com",
        "asset": "https://example.com",
        "endpoint": "/",
        "module": "security_headers",
        "finding_type": "missing_header",
        "title": "Missing Content-Security-Policy Header",
        "severity": "low",
        "confidence": "medium",
        "evidence": "CSP header missing",
        "recommendation": "Add CSP",
        "source": "headers_module",
        "is_potential": True,
        "fingerprint": "fd_123",
        "evidence_id": "ev_123",
    }
    finding.update(overrides)
    return finding


def test_normalize_category_valid() -> None:
    assert normalize_category(" Security_Headers ") == "security_headers"


def test_normalize_category_invalid_unknown() -> None:
    assert normalize_category("bad") == "unknown"


def test_normalize_priority_valid() -> None:
    assert normalize_priority(" High ") == "high"


def test_normalize_priority_invalid_info() -> None:
    assert normalize_priority("urgent") == "info"


def test_normalize_validation_status_invalid_fallback() -> None:
    assert normalize_validation_status("done") == "needs_manual_validation"


def test_detects_exploit() -> None:
    assert contains_unsafe_testing_instruction("exploit the endpoint")


def test_detects_brute_force() -> None:
    assert contains_unsafe_testing_instruction("brute force login")


def test_detects_dos() -> None:
    assert contains_unsafe_testing_instruction("DoS the service")


def test_detects_credential_theft() -> None:
    assert contains_unsafe_testing_instruction("credential theft workflow")


def test_sanitize_manual_steps_replaces_unsafe_step() -> None:
    steps = sanitize_manual_steps(["run exploit payload"])

    assert steps == ["Perform only authorized, non-destructive manual validation for this area."]


def test_sanitize_manual_steps_does_not_mutate_input() -> None:
    original = ["Review safely"]

    sanitize_manual_steps(original)

    assert original == ["Review safely"]


def test_sanitize_manual_steps_removes_duplicates() -> None:
    assert sanitize_manual_steps(["Review safely", "Review safely"]) == ["Review safely"]


def test_sanitize_manual_steps_returns_generic_if_empty() -> None:
    assert sanitize_manual_steps([])


def test_create_recommendation_id_deterministic() -> None:
    first = create_recommendation_id("A", "unknown", "T", ["ev_2", "ev_1"], ["fd_1"])
    second = create_recommendation_id("A", "unknown", "T", ["ev_1", "ev_2"], ["fd_1"])

    assert first == second


def test_recommendation_id_changes_when_title_changes() -> None:
    assert create_recommendation_id("A", "unknown", "T1") != create_recommendation_id("A", "unknown", "T2")


def test_create_manual_test_recommendation_valid() -> None:
    item = create_manual_test_recommendation("Security Headers", "security_headers", "low", "Review CSP", "Review evidence.", ["Review safely."])

    assert isinstance(item, ManualTestRecommendation)
    assert item.recommendation_id.startswith("mt_")


def test_recommendation_has_safety_note() -> None:
    item = create_manual_test_recommendation("Security Headers", "security_headers", "low", "Review CSP", "Review evidence.", ["Review safely."])

    assert DEFAULT_SAFETY_NOTE in item.safety_notes


def test_unsafe_manual_step_not_present_in_recommendation() -> None:
    item = create_manual_test_recommendation("A", "unknown", "low", "T", "D", ["exploit with payload"])

    assert "payload" not in " ".join(item.manual_steps).lower()


def test_empty_title_rejected() -> None:
    try:
        create_manual_test_recommendation("A", "unknown", "low", "", "D", ["Review"])
    except ValueError:
        return
    raise AssertionError("empty title should fail")


def test_empty_description_rejected() -> None:
    try:
        create_manual_test_recommendation("A", "unknown", "low", "T", "", ["Review"])
    except ValueError:
        return
    raise AssertionError("empty description should fail")


def test_to_dict_from_dict_roundtrip() -> None:
    item = create_manual_test_recommendation("A", "unknown", "low", "T", "D", ["Review"])

    assert manual_test_recommendation_from_dict(manual_test_recommendation_to_dict(item)) == item


def test_infer_category_security_headers() -> None:
    assert infer_category_from_finding(make_finding()) == "security_headers"


def test_infer_category_dns_security() -> None:
    assert infer_category_from_finding(make_finding(module="passive_dns", finding_type="dns_record", title="Missing DMARC")) == "dns_security"


def test_infer_category_authentication() -> None:
    assert infer_category_from_finding(make_finding(module="x", finding_type="x", title="Login control review")) == "authentication"


def test_infer_category_authorization() -> None:
    assert infer_category_from_finding(make_finding(module="x", finding_type="x", title="IDOR access control issue")) == "authorization"


def test_infer_category_api_security() -> None:
    assert infer_category_from_finding(make_finding(module="x", finding_type="x", title="Swagger endpoint exposed")) == "api_security"


def test_infer_category_information_disclosure() -> None:
    assert infer_category_from_finding(make_finding(module="x", finding_type="x", title="Server banner disclosure")) == "information_disclosure"


def test_infer_category_transport_security() -> None:
    assert infer_category_from_finding(make_finding(module="x", finding_type="x", title="TLS configuration review")) == "transport_security"


def test_infer_category_rate_limiting() -> None:
    assert infer_category_from_finding(make_finding(module="x", finding_type="x", title="Missing rate limit")) == "rate_limiting"


def test_infer_category_file_upload() -> None:
    assert infer_category_from_finding(make_finding(module="x", finding_type="x", title="File upload review")) == "file_upload"


def test_infer_category_unknown() -> None:
    assert infer_category_from_finding(make_finding(module="x", finding_type="x", title="Unmapped observation")) == "unknown"


def test_infer_priority_high_high() -> None:
    assert infer_priority_from_finding(make_finding(severity="high", confidence="high")) == "high"


def test_infer_priority_medium_medium() -> None:
    assert infer_priority_from_finding(make_finding(severity="medium", confidence="medium")) == "medium"


def test_infer_priority_low() -> None:
    assert infer_priority_from_finding(make_finding(severity="low", confidence="high")) == "low"


def test_infer_priority_info() -> None:
    assert infer_priority_from_finding(make_finding(severity="info", confidence="high")) == "info"


def test_passive_finding_does_not_become_critical() -> None:
    assert infer_priority_from_finding(make_finding(severity="critical", confidence="high")) != "critical"


def test_recommendation_from_finding_creates_recommendation() -> None:
    assert recommendation_from_finding(make_finding()).recommendation_id


def test_recommendation_from_finding_needs_manual_validation() -> None:
    assert recommendation_from_finding(make_finding()).validation_status == "needs_manual_validation"


def test_recommendation_from_finding_has_no_exploit_payload() -> None:
    item = recommendation_from_finding(make_finding())

    assert "payload" not in " ".join(item.manual_steps).lower()


def test_generate_manual_testing_recommendations_handles_list() -> None:
    assert generate_manual_testing_recommendations([make_finding()])


def test_generate_manual_testing_recommendations_deduplicates() -> None:
    result = generate_manual_testing_recommendations([make_finding(), make_finding()])

    assert len(result) == 1


def test_generate_manual_testing_recommendations_sorts_deterministic() -> None:
    result = generate_manual_testing_recommendations(
        [
            make_finding(title="B finding", module="x", severity="low"),
            make_finding(title="A finding", module="x", severity="high", confidence="high"),
        ]
    )

    assert result[0].title == "Manual validation for: A finding"


def test_empty_findings_returns_generic_recommendation() -> None:
    result = generate_manual_testing_recommendations([])

    assert result[0].title == "General manual review"


def test_summary_total_correct() -> None:
    recs = generate_manual_testing_recommendations([make_finding()])

    assert summarize_manual_testing_recommendations(recs)["total"] == 1


def test_summary_by_priority_correct() -> None:
    recs = generate_manual_testing_recommendations([make_finding(severity="low")])

    assert summarize_manual_testing_recommendations(recs)["by_priority"]["low"] == 1


def test_summary_by_category_correct() -> None:
    recs = generate_manual_testing_recommendations([make_finding()])

    assert summarize_manual_testing_recommendations(recs)["by_category"]["security_headers"] == 1


def test_summary_needs_manual_validation_correct() -> None:
    recs = generate_manual_testing_recommendations([make_finding()])

    assert summarize_manual_testing_recommendations(recs)["needs_manual_validation"] == 1


def test_manual_testing_engine_does_not_use_network(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in manual testing engine")

    monkeypatch.setattr(socket, "socket", fail_socket)

    assert generate_manual_testing_recommendations([make_finding()])


def test_manual_testing_engine_does_not_call_external_llm(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("External LLM calls are not allowed")

    monkeypatch.setattr(socket, "socket", fail_socket)

    assert generate_manual_testing_recommendations([make_finding()])


def test_manual_testing_engine_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in manual testing engine")

    monkeypatch.setattr(subprocess, "run", fail_run)

    assert generate_manual_testing_recommendations([])


def test_manual_testing_engine_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in manual testing engine")

    monkeypatch.setattr(os, "system", fail_system)

    recommendation = create_manual_test_recommendation(
        area="Security Headers",
        category="security_headers",
        priority="low",
        title="Review security headers",
        description="Review missing header evidence.",
        manual_steps=["Review the affected response safely."],
    )

    assert recommendation.recommendation_id


def test_manual_testing_source_does_not_use_eval() -> None:
    assert "eval(" not in inspect.getsource(manual_testing_module)


def test_manual_testing_source_does_not_use_exec() -> None:
    assert "exec(" not in inspect.getsource(manual_testing_module)


def test_manual_testing_source_does_not_use_pickle() -> None:
    assert "pickle" not in inspect.getsource(manual_testing_module)
