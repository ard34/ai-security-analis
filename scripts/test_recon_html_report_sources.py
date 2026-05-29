from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.report.json_writer import write_json
from agent.report.recon_html_report import generate_recon_report


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/recon/live_hosts.json", [])
        write_json("outputs/recon/dns_records.json", [])
        write_json("outputs/recon/discovered_subdomains.json", [{"hostname": "app.example.com", "source": "target_input"}])
        write_json("outputs/recon/open_ports.json", [])
        write_json("outputs/recon/services.json", [])
        write_json("outputs/recon/technologies.json", [])
        write_json("outputs/recon/waf_cdn.json", [])
        write_json("outputs/recon/security_headers.json", [])
        write_json("outputs/recon/important_endpoints.json", [])
        write_json("outputs/recon/attack_surface.json", [])
        write_json("outputs/recon/screenshot_index.json", {"screenshots": []})
        write_json("outputs/recon/subdomains_by_source.json", {"target_input": ["app.example.com"], "subfinder": []})
        write_json("outputs/recon/subdomains_all_sources.json", [{"hostname": "app.example.com", "sources": ["target_input"], "confidence": "Medium", "accepted": True}])
        write_json("outputs/recon/dns_validated_hosts.json", [{"hostname": "app.example.com", "resolved": False}])
        write_json("outputs/recon/tool_run_log.json", [{"tool": "subfinder", "status": "Skipped", "duration_seconds": 0, "result_count": 0, "reason": "Tool not installed"}])
        summary = {"target": {"normalized_url": "https://app.example.com"}, "scope": {"allowed_hosts": ["app.example.com"]}, "passive_recon": {}, "status": [], "total_subdomains": 1}
        generate_recon_report(summary)
        content = Path("reports/recon_report.html").read_text(encoding="utf-8")
        for phrase in ["Aktivitas Recon yang Dilakukan AI Agent", "Penemuan Subdomain Berdasarkan Sumber", "Validasi Subdomain", "Ringkasan Eksekusi Tools"]:
            check(phrase in content, f"{phrase} present")
    print("recon_html_report_sources tests passed")


if __name__ == "__main__":
    main()
