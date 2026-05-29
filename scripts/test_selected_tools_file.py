from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.recon.sequential_recon_runner import run_selected_recon_tools
from agent.report.json_writer import read_json, write_json


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def zero_spider(_config, _target_urls, _allowed_hosts=None):
    write_json("outputs/zap/zap_urls.json", [])
    write_json("outputs/zap/zap_spider_summary.json", {"traditional_spider": {"status": "Done", "urls_count": 0}})
    write_json("outputs/zap/zap_endpoint_inventory.json", [])
    return {"status": "Done", "urls_count": 0}


def zero_alerts(_config, target_url=None, allowed_hosts=None):
    write_json("outputs/zap/zap_alerts_raw.json", [])
    write_json("outputs/zap/zap_passive_alerts.json", [])
    return []


def main() -> None:
    config = {"assessment": {"authorization_confirmed": True}, "scan": {"safe_mode": True}, "zap": {"auto_start": False}}
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        with (
            patch("agent.recon.sequential_recon_runner.ensure_zap_running", return_value={"status": "Ready", "version": "2.17.0"}),
            patch("agent.recon.sequential_recon_runner.normalize_target_urls", return_value=["http://localhost"]),
            patch("agent.recon.sequential_recon_runner.run_traditional_spider", side_effect=zero_spider) as spider,
            patch("agent.recon.sequential_recon_runner.collect_zap_messages", return_value=[]),
            patch("agent.recon.sequential_recon_runner.collect_zap_alerts", side_effect=zero_alerts) as alerts,
        ):
            summary = run_selected_recon_tools(config, "localhost", ["zap_traditional_spider", "zap_passive_scan"], "Full Recon")
        selected = read_json("outputs/recon/selected_tools.json", default={})
        ids = selected.get("selected_tool_ids", [])
        check("zap_ensure_running" in ids, "selected tools file includes ensure")
        check("zap_traditional_spider" in ids, "selected tools file includes traditional")
        check("zap_passive_scan" in ids, "selected tools file includes passive")
        check(spider.called, "runner received canonical traditional id")
        check(alerts.called, "runner received canonical passive id")
        rows = {item["step"]: item for item in summary["status"]}
        check(rows["zap_traditional_spider"]["reason"] != "User did not select this tool", "checked traditional not marked unselected")
        check(rows["zap_passive_scan"]["reason"] != "User did not select this tool", "checked passive not marked unselected")
    print("selected_tools_file tests passed")


if __name__ == "__main__":
    main()
