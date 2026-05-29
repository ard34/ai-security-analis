from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.report.json_writer import write_json
from agent.report.report_center import generate_all_reports_html, get_report_status


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def seed() -> None:
    write_json("outputs/recon/recon_summary.json", {"target": {"normalized_url": "https://example.com"}, "scope": {"allowed_hosts": ["example.com"]}, "passive_recon": {}, "status": []})
    for path, data in {
        "outputs/recon/live_hosts.json": [],
        "outputs/recon/dns_records.json": [],
        "outputs/recon/discovered_subdomains.json": [],
        "outputs/recon/open_ports.json": [],
        "outputs/recon/services.json": [],
        "outputs/recon/technologies.json": [],
        "outputs/recon/waf_cdn.json": [],
        "outputs/recon/security_headers.json": [],
        "outputs/recon/important_endpoints.json": [],
        "outputs/recon/attack_surface.json": [],
        "outputs/recon/screenshot_index.json": {"screenshots": []},
        "outputs/potential_findings.json": [],
        "outputs/security_headers.json": {"hosts": [], "findings": []},
        "outputs/technology_fingerprint.json": {"hosts": []},
        "outputs/live_hosts.json": [],
        "outputs/endpoints.json": [],
        "outputs/external_dependencies.json": [],
    }.items():
        write_json(path, data)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        seed()
        paths = generate_all_reports_html({"target": {"base_url": "https://example.com"}, "assessment": {"type": "Test"}})
        check(Path(paths["recon"]).exists(), "recon html generated")
        check(Path(paths["assessment"]).exists(), "assessment html generated")
        check(Path(paths["zap"]).exists(), "zap html generated")
        status = get_report_status()
        check("Laporan Recon" in status, "status includes recon")
    print("report_center tests passed")


if __name__ == "__main__":
    main()
