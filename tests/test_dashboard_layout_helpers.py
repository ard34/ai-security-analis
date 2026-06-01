from app.dashboard import dashboard_modes, domain_mode_enabled
from core.assessment import Assessment


def test_dashboard_helpers():
    assert "Type 1 Source Folder" in dashboard_modes()
    assert domain_mode_enabled(Assessment("a", ["example.com"]).approve(), True) is True
    assert domain_mode_enabled(Assessment("a", ["example.com"]), True) is False

