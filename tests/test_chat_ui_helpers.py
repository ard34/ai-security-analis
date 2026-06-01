from core.models import Finding, ScanResult
from ui.chat import build_chat_context, respond


def test_chat_helpers_are_local():
    result = ScanResult(target="x", workflow="w", findings=[Finding(title="x")])
    assert build_chat_context(result)["finding_count"] == 1
    assert "potential" in respond("findings?", result)

