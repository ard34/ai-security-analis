from core.models import Finding, ScanResult


def test_finding_is_always_potential_and_severity_normalized():
    finding = Finding(title="x", severity="CRIT", is_potential=False)
    assert finding.is_potential is True
    assert finding.severity == "critical"


def test_scan_result_round_trip():
    result = ScanResult(target="example.com", workflow="type2_domain")
    loaded = ScanResult.from_dict(result.to_dict())
    assert loaded.id == result.id
    assert loaded.target == "example.com"

