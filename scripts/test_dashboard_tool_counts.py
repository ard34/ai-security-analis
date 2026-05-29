from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.report.json_writer import write_json
from ui.data_loader import load_attack_surface_counts, load_tool_counts


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        Path("outputs/recon").mkdir(parents=True)
        Path("outputs/zap").mkdir(parents=True)
        Path("outputs/nuclei").mkdir(parents=True)
        write_json("outputs/recon/subdomains_by_source.json", {"subfinder": ["a.example.com"], "amass": ["b.example.com"], "assetfinder": [], "certificate_transparency": ["c.example.com"]})
        write_json("outputs/recon/dns_records.json", [{"type": "A"}])
        write_json("outputs/recon/dns_validated_hosts.json", [{"hostname": "a.example.com"}])
        write_json("outputs/recon/live_hosts.json", [{"hostname": "a.example.com"}])
        write_json("outputs/recon/open_ports.json", [{"port": 443}])
        write_json("outputs/recon/services.json", [{"service": "https"}])
        write_json("outputs/recon/technologies.json", [{"detected": [{"technology": "nginx"}]}])
        write_json("outputs/recon/waf_cdn.json", [{"provider": "Cloudflare"}])
        write_json("outputs/recon/endpoints.json", [{"url": "https://a.example.com/login", "source": "katana"}])
        write_json("outputs/zap/zap_urls.json", [{"url": "https://a.example.com"}])
        write_json("outputs/zap/zap_passive_alerts.json", [{"name": "Header"}])
        write_json("outputs/nuclei/nuclei_results.json", [{"template": "ssl"}])
        write_json("outputs/recon/screenshot_index.json", [{"host": "a.example.com"}])

        counts = {item["tool"]: item["count"] for item in load_tool_counts()}
        check(counts["Subfinder Results"] == 1, "subfinder count")
        check(counts["Certificate Transparency Results"] == 1, "ct count")
        check(counts["OWASP ZAP URLs"] == 1, "zap url count")
        check(counts["Nuclei Findings"] == 1, "nuclei count")
        attack = load_attack_surface_counts()
        check(attack["Live Hosts"] == 1, "attack surface live host count")
        check(attack["Open Ports"] == 1, "attack surface port count")
    print("dashboard_tool_counts tests passed")


if __name__ == "__main__":
    main()
