from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.recon.tool_registry import TOOL_REGISTRY, auto_select_dependencies, canonical_tool_id


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    by_name = {item["display_name"]: item["id"] for item in TOOL_REGISTRY}
    check(by_name["OWASP ZAP Traditional Spider"] == "zap_traditional_spider", "traditional display maps to id")
    check(by_name["OWASP ZAP Passive Scan"] == "zap_passive_scan", "passive display maps to id")
    check(canonical_tool_id("OWASP ZAP Traditional Spider") == "zap_traditional_spider", "canonical traditional")
    check(canonical_tool_id("OWASP ZAP Passive Scan") == "zap_passive_scan", "canonical passive")
    selected = auto_select_dependencies(["zap_traditional_spider", "zap_passive_scan"])
    check("zap_ensure_running" in selected, "zap ensure auto selected")
    check("zap_traditional_spider" in selected, "zap traditional retained")
    check("zap_passive_scan" in selected, "zap passive retained")
    print("zap_checkbox_mapping tests passed")


if __name__ == "__main__":
    main()
