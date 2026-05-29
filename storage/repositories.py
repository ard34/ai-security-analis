from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from storage.database import DEFAULT_DB_PATH, get_connection, initialize_database


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _json_default(value: object) -> object:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return str(value)


class ScanResultRepository:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        initialize_database(self.db_path)

    def save_scan_result(self, scan_result: dict[str, Any]) -> str:
        result = deepcopy(scan_result)
        scan_id = str(result.get("scan_id") or "").strip()
        if not scan_id:
            raise ValueError("scan_result must include scan_id.")
        target = str(result.get("target") or "")
        if not target:
            raise ValueError("scan_result must include target.")
        created_at = _utc_now()
        result_json = json.dumps(result, ensure_ascii=False, sort_keys=True, default=_json_default)
        with get_connection(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO scan_results (
                    scan_id, target, normalized_target, scan_mode, status,
                    started_at, ended_at, result_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    target=excluded.target,
                    normalized_target=excluded.normalized_target,
                    scan_mode=excluded.scan_mode,
                    status=excluded.status,
                    started_at=excluded.started_at,
                    ended_at=excluded.ended_at,
                    result_json=excluded.result_json,
                    created_at=excluded.created_at
                """,
                (
                    scan_id,
                    target,
                    str(result.get("normalized_target") or ""),
                    str(result.get("scan_mode") or ""),
                    str(result.get("status") or ""),
                    str(result.get("started_at") or ""),
                    str(result.get("ended_at") or ""),
                    result_json,
                    created_at,
                ),
            )
        return scan_id

    def get_scan_result(self, scan_id: str) -> dict[str, Any] | None:
        with get_connection(self.db_path) as connection:
            row = connection.execute(
                "SELECT result_json FROM scan_results WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(str(row["result_json"]))

    def list_scan_results(self, limit: int = 20) -> list[dict[str, Any]]:
        safe_limit = min(100, max(1, int(limit or 20)))
        with get_connection(self.db_path) as connection:
            rows = connection.execute(
                """
                SELECT scan_id, target, normalized_target, scan_mode, status,
                       started_at, ended_at, created_at
                FROM scan_results
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_scan_result(self, scan_id: str) -> bool:
        with get_connection(self.db_path) as connection:
            cursor = connection.execute("DELETE FROM scan_results WHERE scan_id = ?", (scan_id,))
            return cursor.rowcount > 0

    def count_scan_results(self) -> int:
        with get_connection(self.db_path) as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM scan_results").fetchone()
        return int(row["count"] if row is not None else 0)

