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
    config = {"assessment": {"authorization_confirmed": True}, "scan": {"safe_mode": True}, "zap": {"auto_start": False}}
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        with (
            patch("agent.recon.sequential_recon_runner.ensure_zap_running", return_value={"status": "Ready", "version": "2.17.0"}),
            patch("agent.recon.sequential_recon_runner.normalize_target_urls", return_value=["http://localhost"]),
            patch("agent.recon.sequential_recon_runner.run_traditional_spider", return_value={"status": "Done", "urls_count": 1}) as spider,
            patch("agent.recon.sequential_recon_runner.collect_zap_messages", return_value=[]),
            patch("agent.recon.sequential_recon_runner.collect_zap_alerts", return_value=[]) as alerts,
        ):
            summary = run_selected_recon_tools(config, "localhost", ["zap_traditional_spider"], "Quick Recon")
        check(spider.called, "traditional spider called")
        check(alerts.called, "alerts collected")
        statuses = {item["step"]: item["status"] for item in summary["status"]}
        check(statuses["zap_traditional_spider"] == "Done", "traditional spider done")
        check(Path("outputs/zap/zap_status.json").exists(), "zap status written")
    print("zap_selected_runs_real_connector tests passed")


if __name__ == "__main__":
    main()
