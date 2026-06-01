from modules.headers import analyze_security_headers


def test_header_analysis_reports_missing_defensive_headers():
    missing = analyze_security_headers({"X-Frame-Options": "DENY"})
    assert "x-frame-options" not in missing
    assert "content-security-policy" in missing

