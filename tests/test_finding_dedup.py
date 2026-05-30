from __future__ import annotations

import inspect
import os
import socket
import subprocess
from copy import deepcopy

import pytest

import core.finding_dedup as dedup_module
from core.finding_dedup import (
    DedupedFinding,
    create_finding_fingerprint,
    deduplicate_findings,
    deduped_finding_to_dict,
    deduped_findings_to_dicts,
    finding_to_deduped_finding,
    merge_deduped_findings,
    normalize_confidence,
    normalize_severity,
    normalize_text,
    summarize_deduped_findings,
)


def make_finding(**overrides) -> dict:
    finding = {
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
    finding.update(overrides)
    return finding


def test_normalize_text_lowercase_and_trim() -> None:
    assert normalize_text("  Hello   WORLD ") == "hello world"


def test_normalize_severity_valid() -> None:
    assert normalize_severity("High") == "high"


def test_normalize_severity_invalid_fallback_info() -> None:
    assert normalize_severity("urgent") == "info"


def test_normalize_confidence_valid() -> None:
    assert normalize_confidence("Medium") == "medium"


def test_normalize_confidence_invalid_fallback_low() -> None:
    assert normalize_confidence("certain") == "low"


def test_fingerprint_deterministic() -> None:
    assert create_finding_fingerprint(make_finding()) == create_finding_fingerprint(make_finding())


def test_fingerprint_same_for_same_finding() -> None:
    first = make_finding()
    second = make_finding()

    assert create_finding_fingerprint(first) == create_finding_fingerprint(second)


def test_fingerprint_ignores_evidence_changes() -> None:
    first = make_finding(evidence="A")
    second = make_finding(evidence="B")

    assert create_finding_fingerprint(first) == create_finding_fingerprint(second)


def test_fingerprint_differs_for_different_endpoint() -> None:
    assert create_finding_fingerprint(make_finding(endpoint="/")) != create_finding_fingerprint(make_finding(endpoint="/login"))


def test_finding_to_deduped_finding_valid() -> None:
    item = finding_to_deduped_finding(make_finding())

    assert isinstance(item, DedupedFinding)
    assert item.occurrences == 1


def test_finding_to_deduped_finding_rejects_non_potential() -> None:
    with pytest.raises(ValueError):
        finding_to_deduped_finding(make_finding(is_potential=False))


def test_default_validation_status() -> None:
    assert finding_to_deduped_finding(make_finding()).validation_status == "needs_manual_validation"


def test_merge_occurrences() -> None:
    merged = merge_deduped_findings(finding_to_deduped_finding(make_finding()), finding_to_deduped_finding(make_finding()))

    assert merged.occurrences == 2


def test_merge_unique_evidence() -> None:
    merged = merge_deduped_findings(
        finding_to_deduped_finding(make_finding(evidence="A")),
        finding_to_deduped_finding(make_finding(evidence="B")),
    )

    assert merged.evidence == ["A", "B"]


def test_merge_unique_recommendations() -> None:
    merged = merge_deduped_findings(
        finding_to_deduped_finding(make_finding(recommendation="Add CSP")),
        finding_to_deduped_finding(make_finding(recommendation="Review CSP")),
    )

    assert merged.recommendations == ["Add CSP", "Review CSP"]


def test_merge_unique_sources() -> None:
    merged = merge_deduped_findings(
        finding_to_deduped_finding(make_finding(source="headers_module")),
        finding_to_deduped_finding(make_finding(source="imported")),
    )

    assert merged.sources == ["headers_module", "imported"]


def test_merge_unique_related_evidence_ids() -> None:
    merged = merge_deduped_findings(
        finding_to_deduped_finding(make_finding(), ["ev_1"]),
        finding_to_deduped_finding(make_finding(), ["ev_1", "ev_2"]),
    )

    assert merged.related_evidence_ids == ["ev_1", "ev_2"]


def test_merge_severity_uses_higher() -> None:
    merged = merge_deduped_findings(
        finding_to_deduped_finding(make_finding(severity="low")),
        finding_to_deduped_finding(make_finding(severity="high")),
    )

    assert merged.severity == "high"


def test_merge_confidence_uses_higher() -> None:
    merged = merge_deduped_findings(
        finding_to_deduped_finding(make_finding(confidence="low")),
        finding_to_deduped_finding(make_finding(confidence="high")),
    )

    assert merged.confidence == "high"


def test_merge_different_fingerprint_rejected() -> None:
    with pytest.raises(ValueError):
        merge_deduped_findings(
            finding_to_deduped_finding(make_finding(endpoint="/")),
            finding_to_deduped_finding(make_finding(endpoint="/login")),
        )


def test_deduplicate_findings_merges_duplicates() -> None:
    result = deduplicate_findings([make_finding(evidence="A"), make_finding(evidence="B")])

    assert len(result) == 1
    assert result[0].occurrences == 2


def test_deduplicate_findings_does_not_mutate_input() -> None:
    findings = [make_finding()]
    original = deepcopy(findings)

    deduplicate_findings(findings)

    assert findings == original


def test_deduplicate_findings_sorting_deterministic() -> None:
    result = deduplicate_findings(
        [
            make_finding(title="B finding", severity="low", endpoint="/b"),
            make_finding(title="A finding", severity="high", endpoint="/a"),
        ]
    )

    assert [item.title for item in result] == ["A finding", "B finding"]


def test_deduped_finding_to_dict_returns_dict() -> None:
    assert isinstance(deduped_finding_to_dict(finding_to_deduped_finding(make_finding())), dict)


def test_deduped_findings_to_dicts_returns_list_dict() -> None:
    result = deduped_findings_to_dicts([finding_to_deduped_finding(make_finding())])

    assert isinstance(result, list)
    assert isinstance(result[0], dict)


def test_summarize_total_unique() -> None:
    summary = summarize_deduped_findings(deduplicate_findings([make_finding()]))

    assert summary["total_unique"] == 1


def test_summarize_total_occurrences() -> None:
    summary = summarize_deduped_findings(deduplicate_findings([make_finding(), make_finding()]))

    assert summary["total_occurrences"] == 2


def test_summary_by_severity() -> None:
    summary = summarize_deduped_findings(deduplicate_findings([make_finding(severity="medium")]))

    assert summary["by_severity"]["medium"] == 1


def test_summary_by_confidence() -> None:
    summary = summarize_deduped_findings(deduplicate_findings([make_finding(confidence="high")]))

    assert summary["by_confidence"]["high"] == 1


def test_summary_by_validation_status() -> None:
    summary = summarize_deduped_findings(deduplicate_findings([make_finding()]))

    assert summary["by_validation_status"]["needs_manual_validation"] == 1


def test_dedup_does_not_use_network(monkeypatch) -> None:
    def fail_socket(*args, **kwargs):
        raise AssertionError("Network access is not allowed in finding deduplication")

    monkeypatch.setattr(socket, "socket", fail_socket)

    assert deduplicate_findings([make_finding()])


def test_dedup_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*args, **kwargs):
        raise AssertionError("subprocess is not allowed in finding deduplication")

    monkeypatch.setattr(subprocess, "run", fail_run)

    assert deduplicate_findings([make_finding()])


def test_dedup_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*args, **kwargs):
        raise AssertionError("os.system is not allowed in finding deduplication")

    monkeypatch.setattr(os, "system", fail_system)

    assert deduplicate_findings([make_finding()])


def test_dedup_source_does_not_use_eval() -> None:
    assert "eval(" not in inspect.getsource(dedup_module)


def test_dedup_source_does_not_use_exec() -> None:
    assert "exec(" not in inspect.getsource(dedup_module)


def test_dedup_source_does_not_use_pickle() -> None:
    assert "pickle" not in inspect.getsource(dedup_module)
