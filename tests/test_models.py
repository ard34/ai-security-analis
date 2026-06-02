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


def test_finding_validation_fields_round_trip():
    finding = Finding(
        title="x",
        validation_status="validation_ready",
        source_locations=[{"file": "app.py", "line": 10}],
        affected_routes=["/x"],
        affected_functions=["handler"],
        confidence_score=0.9,
    )
    loaded = Finding(**finding.to_dict())

    assert loaded.validation_status == "validation_ready"
    assert loaded.source_locations == [{"file": "app.py", "line": 10}]
    assert loaded.affected_routes == ["/x"]
    assert loaded.affected_functions == ["handler"]
    assert loaded.confidence_score == 0.9
    assert loaded.is_potential is True


def test_finding_invalid_validation_status_defaults_to_potential():
    assert Finding(title="x", validation_status="unknown").validation_status == "potential"

