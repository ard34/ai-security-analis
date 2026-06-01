from core.risk import max_severity, normalize_severity, severity_rank


def test_severity_normalization():
    assert normalize_severity("med") == "medium"
    assert normalize_severity("bad") == "info"
    assert severity_rank("high") > severity_rank("low")
    assert max_severity(["low", "critical", "medium"]) == "critical"

