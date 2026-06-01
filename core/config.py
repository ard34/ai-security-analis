from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PREFIX = "AI_SECURITY_ANALYST_"


@dataclass(frozen=True, slots=True)
class Config:
    data_dir: Path = Path("data")
    reports_dir: Path = Path("reports")
    exports_dir: Path = Path("exports")
    logs_dir: Path = Path("logs")
    default_timeout_seconds: float = 5.0
    default_rate_limit_per_second: float = 1.0
    default_scan_budget: int = 8
    max_file_bytes: int = 1_000_000


def _env(name: str, default: str) -> str:
    return os.environ.get(f"{PREFIX}{name}", default)


def load_config() -> Config:
    return Config(
        data_dir=Path(_env("DATA_DIR", "data")),
        reports_dir=Path(_env("REPORTS_DIR", "reports")),
        exports_dir=Path(_env("EXPORTS_DIR", "exports")),
        logs_dir=Path(_env("LOGS_DIR", "logs")),
        default_timeout_seconds=float(_env("DEFAULT_TIMEOUT_SECONDS", "5")),
        default_rate_limit_per_second=float(_env("DEFAULT_RATE_LIMIT_PER_SECOND", "1")),
        default_scan_budget=int(_env("DEFAULT_SCAN_BUDGET", "8")),
        max_file_bytes=int(_env("MAX_FILE_BYTES", "1000000")),
    )

