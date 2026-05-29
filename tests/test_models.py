from __future__ import annotations

import pytest

from core.models import Finding


def test_finding_defaults_to_potential() -> None:
    finding = Finding(
        target="example.com",
        asset="https://app.example.com",
        endpoint="/login",
        module="security_headers",
        finding_type="missing_header",
        title="Missing Content-Security-Policy Header",
        severity="low",
        confidence="medium",
        evidence="Content-Security-Policy header not present",
        recommendation="Implement a restrictive Content-Security-Policy header.",
        source="headers_module",
    )

    assert finding.is_potential is True
    assert finding.to_dict()["is_potential"] is True


def test_invalid_finding_severity_rejected() -> None:
    with pytest.raises(ValueError):
        Finding(
            target="example.com",
            asset="https://app.example.com",
            endpoint="/login",
            module="security_headers",
            finding_type="missing_header",
            title="Invalid Severity",
            severity="urgent",
            confidence="medium",
            evidence="evidence",
            recommendation="recommendation",
            source="test",
        )


def test_invalid_finding_confidence_rejected() -> None:
    with pytest.raises(ValueError):
        Finding(
            target="example.com",
            asset="https://app.example.com",
            endpoint="/login",
            module="security_headers",
            finding_type="missing_header",
            title="Invalid Confidence",
            severity="low",
            confidence="certain",
            evidence="evidence",
            recommendation="recommendation",
            source="test",
        )
