from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.app import selected_tool_ids_from_checks


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    selected = selected_tool_ids_from_checks({"subfinder": True, "dnsx": True, "zap_traditional_spider": True, "zap_passive_scan": False})
    check("subfinder" in selected, "subfinder selected")
    check("dnsx" in selected, "dnsx selected")
    check("zap_traditional_spider" in selected, "zap traditional selected")
    check("zap_ensure_running" in selected, "zap dependency selected")
    check("zap_passive_scan" not in selected, "unchecked passive scan excluded")
    print("recon_checkbox_selected_tools tests passed")


if __name__ == "__main__":
    main()
