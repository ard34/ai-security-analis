from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.report.json_writer import read_json, write_json

LOG_PATH = Path("outputs/recon/recon_progress.jsonl")
LATEST_PATH = Path("outputs/recon/recon_progress_latest.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_progress_log() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("", encoding="utf-8")
    write_json(LATEST_PATH, [])


def _append(event: dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        import json

        handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    latest = read_json(LATEST_PATH, default=[]) or []
    latest.append(event)
    write_json(LATEST_PATH, latest[-200:])


def log_step(step: str, status: str, message: str, details: dict[str, Any] | None = None) -> None:
    _append({"timestamp": _now(), "step": step, "tool": "", "status": status, "message": message, "details": details or {}})


def log_tool_start(tool: str, command: list[str] | str | None = None, target: str | None = None) -> None:
    _append({"timestamp": _now(), "step": "Tool Execution", "tool": tool, "status": "running", "message": f"{tool} mulai dijalankan.", "details": {"command": command, "target": target}})


def log_tool_done(tool: str, count: int = 0, details: dict[str, Any] | None = None) -> None:
    _append({"timestamp": _now(), "step": "Tool Execution", "tool": tool, "status": "done", "message": f"{tool} selesai. Hasil: {count}.", "details": details or {}})


def log_tool_skipped(tool: str, reason: str) -> None:
    _append({"timestamp": _now(), "step": "Tool Execution", "tool": tool, "status": "skipped", "message": f"{tool} dilewati: {reason}", "details": {"reason": reason}})


def log_tool_failed(tool: str, reason: str) -> None:
    _append({"timestamp": _now(), "step": "Tool Execution", "tool": tool, "status": "failed", "message": f"{tool} gagal: {reason}", "details": {"reason": reason}})


def log_tool_timeout(tool: str, reason: str) -> None:
    _append({"timestamp": _now(), "step": "Tool Execution", "tool": tool, "status": "timeout", "message": f"{tool} waktu habis: {reason}", "details": {"reason": reason}})


def get_progress_log() -> list[dict[str, Any]]:
    return read_json(LATEST_PATH, default=[]) or []
