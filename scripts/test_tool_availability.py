from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.recon.tool_availability import check_tool_availability


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        with patch("agent.recon.tool_availability.command_exists", side_effect=lambda tool: tool == "subfinder"):
            results = check_tool_availability()
        by_tool = {item["tool"]: item for item in results}
        check(by_tool["subfinder"]["installed"], "installed tool marked")
        check(not by_tool["amass"]["installed"], "missing tool marked")
        check(Path("outputs/recon/tool_availability.json").exists(), "availability output written")
    print("tool_availability tests passed")


if __name__ == "__main__":
    main()
