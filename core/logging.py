from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import utc_now
from core.policies import redact_mapping


class AuditLogger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, action: str, **fields: Any) -> dict[str, Any]:
        payload = {"ts": utc_now(), "action": action, **redact_mapping(fields)}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
        return payload


def read_audit_log(path: str | Path) -> list[dict[str, Any]]:
    audit_path = Path(path)
    if not audit_path.exists():
        return []
    events = []
    with audit_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                events.append(json.loads(line))
    return events

