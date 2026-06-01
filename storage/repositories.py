from __future__ import annotations

import json
import sqlite3

from core.models import ScanResult
from storage.database import initialize


class ScanRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        initialize(connection)

    def save(self, result: ScanResult) -> None:
        payload = result.to_dict()
        self.connection.execute(
            "INSERT OR REPLACE INTO scans (id, workflow, target, created_at, payload_json) VALUES (?, ?, ?, ?, ?)",
            (result.id, result.workflow, result.target, result.started_at, json.dumps(payload, sort_keys=True)),
        )
        self.connection.commit()

    def get(self, scan_id: str) -> ScanResult | None:
        row = self.connection.execute("SELECT payload_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return ScanResult.from_dict(json.loads(row["payload_json"]))

    def list(self) -> list[dict[str, str]]:
        rows = self.connection.execute("SELECT id, workflow, target, created_at FROM scans ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

