from core.config import load_config


def test_config_reads_prefixed_environment(monkeypatch):
    monkeypatch.setenv("AI_SECURITY_ANALYST_DEFAULT_SCAN_BUDGET", "3")
    assert load_config().default_scan_budget == 3

