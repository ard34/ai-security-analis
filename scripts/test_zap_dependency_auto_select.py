from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.recon.sequential_recon_runner import build_execution_plan
from agent.recon.tool_registry import auto_select_dependencies


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    selected = auto_select_dependencies(["zap_ajax_spider"])
    check("zap_ensure_running" in selected, "ensure added for ajax")
    plan = {item["step"]: item for item in build_execution_plan(["zap_ajax_spider"])}
    check(plan["zap_ensure_running"]["status"] == "Pending", "ensure planned")
    check(plan["zap_ajax_spider"]["status"] == "Pending", "ajax planned")
    check(plan["zap_traditional_spider"]["status"] == "Skipped", "traditional skipped when unchecked")
    print("zap_dependency_auto_select tests passed")


if __name__ == "__main__":
    main()
