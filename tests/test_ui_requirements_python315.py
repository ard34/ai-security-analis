from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_ui_requirements_skip_streamlit_stack_on_bleeding_edge_python():
    content = read("requirements-ui.txt")
    requirement_lines = [
        line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#")
    ]

    assert 'streamlit>=1.30; python_version < "3.14"' in content
    assert 'reportlab>=4.0; python_version < "3.14"' in content
    assert not any(line.startswith("pyarrow") for line in requirement_lines)
    assert not any(line.startswith("pandas") for line in requirement_lines)


def test_docs_explain_python_315_ui_dependency_fallback():
    combined = "\n".join(
        [
            read("README.md"),
            read("docs/ui-smoke-test-runbook.md"),
            read("docs/ui-manual-test-session.md"),
            read("docs/ui-runtime-validation-supported-python.md"),
        ]
    ).lower()

    assert "python 3.14/3.15" in combined
    assert "requirements-ui.txt" in combined
    assert "skips the optional streamlit stack" in combined
    assert "core cli/testing" in combined
