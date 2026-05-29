from __future__ import annotations

from agent.report.json_writer import read_json


def load_http_history(path: str = "outputs/http_history.json") -> list[dict[str, object]]:
    return read_json(path, default=[]) or []
