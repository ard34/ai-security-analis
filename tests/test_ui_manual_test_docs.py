from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SESSION_DOC = ROOT / "docs" / "ui-manual-test-session.md"
RESULT_TEMPLATE = ROOT / "docs" / "ui-manual-test-result-template.md"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8").lower()


def test_manual_test_session_doc_exists():
    assert SESSION_DOC.is_file()


def test_manual_test_result_template_exists():
    assert RESULT_TEMPLATE.is_file()


def test_manual_session_mentions_streamlit_command():
    assert "streamlit run ui/app.py" in text(SESSION_DOC)


def test_manual_session_mentions_safety_banner_and_workspace():
    content = text(SESSION_DOC)

    assert "safety banner" in content
    assert "workspace" in content


def test_manual_session_mentions_validation_status_and_unsafe_chat_rejection():
    content = text(SESSION_DOC)

    assert "validation status" in content
    assert "chat rejects unsafe request" in content


def test_manual_session_mentions_export_json_html_pdf():
    content = text(SESSION_DOC)

    assert "export json" in content
    assert "export html" in content
    assert "export pdf" in content


def test_manual_session_mentions_stop_conditions():
    assert "stop conditions" in text(SESSION_DOC)


def test_result_template_mentions_bugs_safety_and_final_decision():
    content = text(RESULT_TEMPLATE)

    assert "bugs found" in content
    assert "safety concerns" in content
    assert "final decision" in content


def test_manual_test_docs_do_not_contain_fake_secrets():
    combined = text(SESSION_DOC) + "\n" + text(RESULT_TEMPLATE)

    forbidden = ["authorization: bearer", "password=", "api_key=", "cookie=", "session="]
    for item in forbidden:
        assert item not in combined
