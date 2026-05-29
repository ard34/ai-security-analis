from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.core.target_normalizer import normalize_target
from agent.recon.recon_progress import init_progress_log
from agent.recon.subdomain_discovery_multi import discover_subdomains_multi
from agent.report.json_writer import read_json, write_json


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        init_progress_log()
        write_json("outputs/recon/dns_records.json", [{"type": "MX", "name": "example.com", "value": "mail.example.com."}])
        normalized = normalize_target("https://app.example.com", "Pre-Launch Black Box Testing")
        with patch("agent.recon.subdomain_discovery_multi.command_exists", return_value=False), patch("agent.recon.subdomain_discovery_multi.collect_ct_subdomains", return_value=[{"hostname": "ct.example.com"}]):
            results = discover_subdomains_multi({"assessment": {"authorization_confirmed": True}}, normalized)
        by_source = read_json("outputs/recon/subdomains_by_source.json")
        all_sources = read_json("outputs/recon/subdomains_all_sources.json")
        tool_runs = read_json("outputs/recon/tool_run_log.json")
        check("example.com" in by_source["target_input"], "root domain included")
        check("app.example.com" in by_source["target_input"], "input hostname included")
        check("subfinder" in by_source and len(by_source["subfinder"]) == 0, "subfinder source visible at zero")
        check(any(item["hostname"] == "app.example.com" for item in results), "accepted input hostname")
        check(any(item["tool"] == "subfinder" and item["status"] == "Skipped" for item in tool_runs), "missing tool marked skipped")
        check(Path("outputs/recon/subdomains.txt").exists(), "subdomains text written")
        check(len(all_sources) >= 1, "all source output visible")
    print("subdomain_source_breakdown tests passed")


if __name__ == "__main__":
    main()
