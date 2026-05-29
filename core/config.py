from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
from typing import Mapping


VALID_SCAN_MODES = {"strict", "safe", "standard"}
VALID_ENVIRONMENTS = {"local", "test", "dev", "prod"}
VALID_DATABASE_SUFFIXES = {".sqlite3", ".db"}
REMOTE_DATABASE_PREFIXES = ("http://", "https://", "postgres://", "mysql://")


@dataclass(frozen=True)
class AppConfig:
    app_name: str = "AI Security Analyst"
    environment: str = "local"
    default_scan_mode: str = "safe"
    database_path: Path = Path("data/ai_security_analyst.sqlite3")
    data_dir: Path = Path("data")
    reports_dir: Path = Path("reports")
    exports_dir: Path = Path("exports")
    max_history_limit: int = 20
    enable_dashboard_storage: bool = True
    enable_json_import: bool = True
    enable_pdf_export: bool = True


def _clean_env_value(value: object) -> str:
    return str(value).strip().strip('"').strip("'")


def parse_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = _clean_env_value(value).lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    return default


def parse_int(
    value: str | int | None,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    try:
        parsed = int(value) if not isinstance(value, bool) and value is not None else int(default)
    except (TypeError, ValueError):
        parsed = int(default)
    if minimum is not None and parsed < minimum:
        parsed = minimum
    if maximum is not None and parsed > maximum:
        parsed = maximum
    return parsed


def _env(source: Mapping[str, str], key: str, default: str) -> str:
    value = source.get(key)
    return _clean_env_value(value) if value is not None else default


def _env_path(source: Mapping[str, str], key: str, default: Path) -> Path:
    return Path(_env(source, key, str(default)))


def load_config(env: dict[str, str] | None = None) -> AppConfig:
    source: Mapping[str, str] = os.environ if env is None else env
    config = AppConfig(
        app_name=_env(source, "AI_SECURITY_ANALYST_APP_NAME", "AI Security Analyst"),
        environment=_env(source, "AI_SECURITY_ANALYST_ENVIRONMENT", "local"),
        default_scan_mode=_env(source, "AI_SECURITY_ANALYST_DEFAULT_SCAN_MODE", "safe"),
        database_path=_env_path(source, "AI_SECURITY_ANALYST_DATABASE_PATH", Path("data/ai_security_analyst.sqlite3")),
        data_dir=_env_path(source, "AI_SECURITY_ANALYST_DATA_DIR", Path("data")),
        reports_dir=_env_path(source, "AI_SECURITY_ANALYST_REPORTS_DIR", Path("reports")),
        exports_dir=_env_path(source, "AI_SECURITY_ANALYST_EXPORTS_DIR", Path("exports")),
        max_history_limit=parse_int(
            source.get("AI_SECURITY_ANALYST_MAX_HISTORY_LIMIT"),
            default=20,
            minimum=1,
            maximum=100,
        ),
        enable_dashboard_storage=parse_bool(source.get("AI_SECURITY_ANALYST_ENABLE_DASHBOARD_STORAGE"), default=True),
        enable_json_import=parse_bool(source.get("AI_SECURITY_ANALYST_ENABLE_JSON_IMPORT"), default=True),
        enable_pdf_export=parse_bool(source.get("AI_SECURITY_ANALYST_ENABLE_PDF_EXPORT"), default=True),
    )
    validate_config(config)
    return config


def _is_remote_path(path: Path) -> bool:
    text = str(path).strip().lower()
    return text.startswith(REMOTE_DATABASE_PREFIXES) or text.startswith(("http:/", "https:/", "postgres:/", "mysql:/")) or "://" in text


def _validate_non_empty_path(path: Path, label: str) -> None:
    if not str(path).strip():
        raise ValueError(f"{label} path cannot be empty.")


def validate_config(config: AppConfig) -> None:
    if config.default_scan_mode not in VALID_SCAN_MODES:
        raise ValueError("default_scan_mode must be one of: strict, safe, standard.")
    if config.environment not in VALID_ENVIRONMENTS:
        raise ValueError("environment must be one of: local, test, dev, prod.")
    if not 1 <= int(config.max_history_limit) <= 100:
        raise ValueError("max_history_limit must be between 1 and 100.")

    _validate_non_empty_path(config.database_path, "database")
    _validate_non_empty_path(config.data_dir, "data_dir")
    _validate_non_empty_path(config.reports_dir, "reports_dir")
    _validate_non_empty_path(config.exports_dir, "exports_dir")

    if _is_remote_path(config.database_path):
        raise ValueError("database_path must be a local SQLite path, not a URL.")
    if config.database_path.suffix.lower() not in VALID_DATABASE_SUFFIXES:
        raise ValueError("database_path must end with .sqlite3 or .db.")


def ensure_config_directories(config: AppConfig) -> None:
    for directory in (config.data_dir, config.reports_dir, config.exports_dir, config.database_path.parent):
        if str(directory).strip():
            directory.mkdir(parents=True, exist_ok=True)
