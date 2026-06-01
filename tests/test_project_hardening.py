from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_pyproject_exists_and_contains_pytest_config():
    content = read("pyproject.toml")

    assert "[tool.pytest.ini_options]" in content
    assert "testpaths" in content
    assert "[tool.ruff]" in content


def test_makefile_contains_required_commands():
    content = read("Makefile")

    for command in ["test:", "lint:", "format:", "safety:", "run-dashboard:", "clean:"]:
        assert command in content
    assert "pytest -q" in content
    assert "ruff check" in content
    assert "scan-domain" not in content


def test_dockerfile_does_not_include_secrets_or_live_scan_default():
    content = read("Dockerfile").lower()

    forbidden = ["authorization", "password", "api_key", "apikey", "token=", "cookie", "scan-domain"]
    for item in forbidden:
        assert item not in content
    assert "streamlit" in content
    assert "dashboard.py" in content


def test_docker_compose_does_not_include_secrets():
    content = read("docker-compose.yml").lower()

    forbidden = ["authorization", "password", "api_key", "apikey", "token=", "cookie", "scan-domain"]
    for item in forbidden:
        assert item not in content
    assert "./data:/app/data" in content
    assert "./logs:/app/logs" in content


def test_ci_workflow_runs_pytest_and_lint():
    content = read(".github/workflows/ci.yml")

    assert "pytest -q" in content
    assert "ruff check ." in content
    assert "scan-domain" not in content


def test_dockerignore_excludes_sensitive_and_generated_dirs():
    lines = {line.strip() for line in read(".dockerignore").splitlines() if line.strip()}

    for item in [".git", ".venv", "venv", "__pycache__", ".pytest_cache", "data", "reports", "exports", "logs", ".env"]:
        assert item in lines
