from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.recon.sequential_recon_runner import run_selected_recon_tools


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    config = {"assessment": {"authorization_confirmed": True}, "scan": {"safe_mode": True}, "tools": {}, "recon": {"enable_port_scan": False}}
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        with patch("agent.recon.sequential_recon_runner.command_exists", return_value=False):
            summary = run_selected_recon_tools(config, "localhost", ["DNS Records", "Subfinder"], "Quick Recon")
        check(Path("outputs/recon/recon_progress.jsonl").exists(), "progress log written")
        check(Path("outputs/recon/tool_run_log.json").exists(), "tool log written")
        check(Path("outputs/recon/recon_summary.json").exists(), "summary written")
        statuses = {item["step"]: item["status"] for item in summary["status"]}
        check(statuses["subfinder"] == "Skipped", "missing subfinder skipped")
        check(statuses["nmap_fast"] == "Skipped", "unselected nmap skipped")
        check(summary["run_status"] in {"Completed", "Failed"}, "runner returned final status")
    print("sequential_recon_runner tests passed")


if __name__ == "__main__":
    main()
