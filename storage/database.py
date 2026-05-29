from __future__ import annotations

from pathlib import Path
import sqlite3


DEFAULT_DB_PATH = Path("data/ai_security_analyst.sqlite3")


def ensure_parent_directory(db_path: str | Path) -> None:
    Path(db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)


def get_connection(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    ensure_parent_directory(db_path)
    connection = sqlite3.connect(str(Path(db_path).expanduser()))
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    with get_connection(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL UNIQUE,
                target TEXT NOT NULL,
                normalized_target TEXT,
                scan_mode TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT,
                ended_at TEXT,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id
            ON scan_results(scan_id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_results_created_at
            ON scan_results(created_at)
            """
        )

