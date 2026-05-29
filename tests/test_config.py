from __future__ import annotations

import os
import socket
import subprocess

import pytest

from core.config import (
    AppConfig,
    ensure_config_directories,
    load_config,
    parse_bool,
    parse_int,
)


def test_load_config_returns_app_config() -> None:
    assert isinstance(load_config({}), AppConfig)


def test_default_app_name_is_correct() -> None:
    assert load_config({}).app_name == "AI Security Analyst"


def test_default_environment_is_local() -> None:
    assert load_config({}).environment == "local"


def test_default_scan_mode_is_safe() -> None:
    assert load_config({}).default_scan_mode == "safe"


def test_default_database_path_is_correct() -> None:
    assert str(load_config({}).database_path) == "data/ai_security_analyst.sqlite3"


def test_env_override_app_name_works() -> None:
    config = load_config({"AI_SECURITY_ANALYST_APP_NAME": "Custom Analyst"})
    assert config.app_name == "Custom Analyst"


def test_env_override_database_path_works() -> None:
    config = load_config({"AI_SECURITY_ANALYST_DATABASE_PATH": "tmp/custom.db"})
    assert str(config.database_path) == "tmp/custom.db"


def test_env_override_default_scan_mode_works() -> None:
    config = load_config({"AI_SECURITY_ANALYST_DEFAULT_SCAN_MODE": "strict"})
    assert config.default_scan_mode == "strict"


def test_invalid_scan_mode_rejected() -> None:
    with pytest.raises(ValueError):
        load_config({"AI_SECURITY_ANALYST_DEFAULT_SCAN_MODE": "danger"})


def test_invalid_environment_rejected() -> None:
    with pytest.raises(ValueError):
        load_config({"AI_SECURITY_ANALYST_ENVIRONMENT": "staging"})


def test_invalid_database_url_rejected() -> None:
    with pytest.raises(ValueError):
        load_config({"AI_SECURITY_ANALYST_DATABASE_PATH": "https://example.com/db.sqlite3"})


def test_non_sqlite_database_extension_rejected() -> None:
    with pytest.raises(ValueError):
        load_config({"AI_SECURITY_ANALYST_DATABASE_PATH": "data/project.postgres"})


def test_parse_bool_true() -> None:
    assert parse_bool("true") is True


def test_parse_bool_false() -> None:
    assert parse_bool("false") is False


def test_parse_bool_none_uses_default() -> None:
    assert parse_bool(None, default=True) is True


def test_parse_int_returns_int() -> None:
    assert parse_int("10", default=1) == 10


def test_parse_int_clamps_minimum() -> None:
    assert parse_int("0", default=5, minimum=1) == 1


def test_parse_int_clamps_maximum() -> None:
    assert parse_int("200", default=5, maximum=100) == 100


def test_parse_int_invalid_uses_default() -> None:
    assert parse_int("not-int", default=7) == 7


def test_ensure_config_directories_creates_directories(tmp_path) -> None:
    config = AppConfig(
        database_path=tmp_path / "data" / "test.sqlite3",
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        exports_dir=tmp_path / "exports",
    )
    ensure_config_directories(config)
    assert config.data_dir.exists()
    assert config.reports_dir.exists()
    assert config.exports_dir.exists()
    assert config.database_path.parent.exists()


def test_ensure_config_directories_is_idempotent(tmp_path) -> None:
    config = AppConfig(
        database_path=tmp_path / "data" / "test.sqlite3",
        data_dir=tmp_path / "data",
        reports_dir=tmp_path / "reports",
        exports_dir=tmp_path / "exports",
    )
    ensure_config_directories(config)
    ensure_config_directories(config)
    assert config.data_dir.exists()


def test_config_does_not_use_network(monkeypatch) -> None:
    def fail_socket(*_args, **_kwargs):
        raise AssertionError("Network access is not allowed in config loader")

    monkeypatch.setattr(socket, "socket", fail_socket)
    assert load_config({}).app_name == "AI Security Analyst"


def test_config_does_not_use_subprocess(monkeypatch) -> None:
    def fail_run(*_args, **_kwargs):
        raise AssertionError("subprocess is not allowed in config loader")

    monkeypatch.setattr(subprocess, "run", fail_run)
    assert load_config({}).default_scan_mode == "safe"


def test_config_does_not_use_os_system(monkeypatch) -> None:
    def fail_system(*_args, **_kwargs):
        raise AssertionError("os.system is not allowed in config loader")

    monkeypatch.setattr(os, "system", fail_system)
    assert load_config({}).environment == "local"
