from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.recon.sequential_recon_runner import build_execution_plan


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    plan = build_execution_plan(["DNS Records", "Subfinder", "HTTPx", "Attack Surface Mapping"])
    by_step = {item["step"]: item for item in plan}
    check(by_step["Target Normalization"]["status"] == "Pending", "normalization always planned")
    check(by_step["dns_records"]["status"] == "Pending", "selected dns planned")
    check(by_step["subfinder"]["status"] == "Pending", "selected subfinder planned")
    check(by_step["httpx"]["status"] == "Pending", "httpx alias planned")
    alias_plan = build_execution_plan(["Katana light crawl", "Technology Fingerprint"])
    alias = {item["step"]: item for item in alias_plan}
    check(alias["katana"]["status"] == "Pending", "katana alias planned")
    check(alias["whatweb"]["status"] == "Pending", "technology alias planned")
    check(by_step["nmap_fast"]["status"] == "Skipped", "unselected tool skipped")
    check(by_step["nmap_fast"]["reason"] == "User did not select this tool", "unselected reason")
    print("selected_recon_tools tests passed")


if __name__ == "__main__":
    main()
