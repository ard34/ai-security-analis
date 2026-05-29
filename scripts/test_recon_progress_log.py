from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.recon.recon_progress import get_progress_log, init_progress_log, log_step, log_tool_done, log_tool_skipped


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        init_progress_log()
        log_step("Penemuan Subdomain", "running", "Mulai")
        log_tool_skipped("subfinder", "Tool not installed")
        log_tool_done("certificate_transparency", 2)
        log = get_progress_log()
        check(Path("outputs/recon/recon_progress.jsonl").exists(), "jsonl written")
        check(len(log) == 3, "latest log written")
        check(log[1]["status"] == "skipped", "skipped recorded")
    print("recon_progress_log tests passed")


if __name__ == "__main__":
    main()
