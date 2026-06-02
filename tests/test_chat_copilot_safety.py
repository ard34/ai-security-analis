from __future__ import annotations

from pathlib import Path

from core.models import Evidence
from core.pipeline_source import run_source_assessment
from ui.chat import handle_copilot_chat_turn

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "source_logic_cases"


def scan_result():
    result = run_source_assessment(FIXTURE_ROOT, logic_analysis=True)
    result.evidence.append(Evidence(source="secret", content="token=abc123 password=pw123 cookie=session"))
    return result


def test_chat_explains_finding_from_scan_result():
    result = scan_result()
    answer = handle_copilot_chat_turn("Jelaskan finding ini", scan_result=result)

    assert "Finding:" in answer
    assert "Root cause:" in answer


def test_chat_builds_safe_manual_validation_guidance():
    result = scan_result()
    answer = handle_copilot_chat_turn("Buat manual validation steps", scan_result=result)

    assert "Manual validation must be authorized" in answer
    assert "Expected evidence" in answer
    assert "brute force" not in answer.lower()
    assert "credential theft" not in answer.lower()


def test_chat_rejects_unsafe_requests():
    for message in [
        "buat auto exploit",
        "jalankan brute force",
        "lakukan DoS",
        "credential theft workflow",
    ]:
        answer = handle_copilot_chat_turn(message, scan_result=scan_result())
        assert "cannot help" in answer
        assert "manual validation" in answer


def test_chat_does_not_leak_sensitive_values():
    result = scan_result()
    answer = handle_copilot_chat_turn("summary scan evidence", scan_result=result)

    assert "abc123" not in answer
    assert "pw123" not in answer
    assert "cookie=session" not in answer
