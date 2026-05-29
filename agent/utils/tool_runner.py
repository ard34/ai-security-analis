from __future__ import annotations

import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.recon.recon_progress import log_tool_done, log_tool_failed, log_tool_start, log_tool_timeout
from agent.recon.recon_progress import log_tool_skipped
from agent.report.json_writer import read_json, write_json


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_run(entry: dict[str, Any], path: str = "outputs/recon/tool_run_log.json") -> None:
    runs = read_json(path, default=[]) or []
    runs.append(entry)
    write_json(path, runs)


def run_tool(command: list[str], timeout: int, tool_name: str, output_path: str | None = None, stderr_path: str | None = None, target: str | None = None) -> dict[str, Any]:
    started = time.monotonic()
    started_at = _now()
    log_tool_start(tool_name, command, target)
    stdout_text = ""
    stderr_text = ""
    status = "Done"
    exit_code: int | None = None
    reason = ""
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        stdout_text = completed.stdout or ""
        stderr_text = completed.stderr or ""
        exit_code = completed.returncode
        if completed.returncode != 0:
            status = "Failed"
            reason = stderr_text.strip()[:500] or f"exit_code={completed.returncode}"
    except subprocess.TimeoutExpired as exc:
        status = "Timeout"
        reason = str(exc)
        stdout_text = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr_text = (exc.stderr or "") if isinstance(exc.stderr, str) else ""

    if output_path and stdout_text:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(stdout_text, encoding="utf-8")
    if stderr_path and stderr_text:
        Path(stderr_path).parent.mkdir(parents=True, exist_ok=True)
        Path(stderr_path).write_text(stderr_text, encoding="utf-8")
    finished_at = _now()
    duration = round(time.monotonic() - started, 3)
    result_count = len([line for line in stdout_text.splitlines() if line.strip()])
    entry = {
        "tool": tool_name,
        "command": command,
        "target": target or "",
        "status": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": duration,
        "exit_code": exit_code,
        "stdout_path": output_path or "",
        "stderr_path": stderr_path or "",
        "result_count": result_count,
        "reason": reason,
    }
    _append_run(entry)
    if status == "Done":
        log_tool_done(tool_name, result_count, {"duration_seconds": duration})
    elif status == "Timeout":
        log_tool_timeout(tool_name, reason)
    else:
        log_tool_failed(tool_name, reason)
    return {"stdout": stdout_text, "stderr": stderr_text, **entry}


def record_tool_skipped(tool_name: str, reason: str, target: str | None = None) -> dict[str, Any]:
    now = _now()
    entry = {
        "tool": tool_name,
        "command": [],
        "target": target or "",
        "status": "Skipped",
        "started_at": now,
        "finished_at": now,
        "duration_seconds": 0,
        "exit_code": None,
        "stdout_path": "",
        "stderr_path": "",
        "result_count": 0,
        "reason": reason,
    }
    _append_run(entry)
    log_tool_skipped(tool_name, reason)
    return entry
