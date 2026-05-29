from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.recon.recon_orchestrator import run_recon_v2
from agent.report.json_writer import write_json


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def config(assessment_type: str) -> dict[str, object]:
    return {
        "assessment": {"type": assessment_type, "authorization_confirmed": True},
        "scan": {"safe_mode": True, "max_urls_per_host": 10},
        "tools": {"subfinder": "definitely-missing-subfinder", "nmap": "definitely-missing-nmap", "katana": "definitely-missing-katana", "whatweb": "definitely-missing-whatweb"},
        "recon": {"enable_port_scan": True},
        "scope": {"include_root_domain": True, "include_discovered_subdomains": True, "require_http_alive": True},
    }


def fake_passive(_config: dict[str, object], domain: str, output_dir: str) -> dict[str, object]:
    write_json(f"{output_dir}/dns_records.json", [{"type": "A", "name": domain, "value": "192.0.2.10", "ttl": ""}])
    write_json(f"{output_dir}/whois.json", {"status": "skipped"})
    write_json(f"{output_dir}/ct_subdomains.json", {"subdomains": [], "status": "skipped"})
    write_json(f"{output_dir}/public_repo_recon.json", {"status": "skipped"})
    return {"dns_records": 1, "ct_subdomains": 0, "public_repo_recon": "skipped", "whois": "skipped"}


def fake_live(_config: dict[str, object], normalized: object, output_dir: str) -> list[dict[str, object]]:
    item = {"hostname": normalized.hostname, "url": normalized.normalized_url, "status_code": 200, "title": "Test", "webserver": "nginx", "technologies": ["React"], "content_type": "text/html", "response_time": 0.1, "target_type": normalized.target_kind, "source": "mock"}
    write_json(f"{output_dir}/live_hosts.json", [item])
    write_json("outputs/live_hosts.json", [{"hostname": item["hostname"], "url": item["url"], "status_code": 200, "title": "Test", "webserver": "nginx", "tech": ["React"], "source": "mock"}])
    return [item]


def fake_ports(_config: dict[str, object], _hosts: list[str], _normalized: object, output_dir: str) -> dict[str, list[dict[str, object]]]:
    write_json(f"{output_dir}/open_ports.json", [])
    write_json(f"{output_dir}/services.json", [])
    return {"open_ports": [], "services": []}


def fake_web(_config: dict[str, object], live_hosts: list[dict[str, object]], output_dir: str) -> dict[str, object]:
    headers = [{"host": live_hosts[0]["hostname"], "missing_csp": True, "missing_hsts": False, "missing_x_frame_options": False, "missing_x_content_type_options": False, "cookie_issues": [], "cors_notes": "", "issue_count": 1}]
    tech = [{"host": live_hosts[0]["hostname"], "url": live_hosts[0]["url"], "detected": [{"technology": "React"}]}]
    waf = []
    write_json(f"{output_dir}/security_headers.json", headers)
    write_json(f"{output_dir}/technologies.json", tech)
    write_json(f"{output_dir}/waf_cdn.json", waf)
    write_json("outputs/technology_fingerprint.json", {"hosts": tech})
    write_json("outputs/security_headers.json", {"hosts": headers, "findings": []})
    return {"security_headers": headers, "technologies": tech, "waf_cdn": waf}


def fake_katana(_allowed_urls: list[str], _allowed_hosts: list[str], _max_urls: int, _command: str, output_path: str) -> list[str]:
    endpoints = [f"{_allowed_urls[0].rstrip('/')}/login", f"{_allowed_urls[0].rstrip('/')}/api/orders"]
    write_json(output_path, endpoints)
    write_json("outputs/external_dependencies.json", [])
    return endpoints


def fake_screenshots(_live_hosts: list[dict[str, object]], _allowed_hosts: list[str], _output_dir: str) -> list[dict[str, object]]:
    write_json("outputs/recon/screenshot_index.json", {"status": "skipped", "screenshots": []})
    return []


def run_case(target: str, assessment: str) -> dict[str, object]:
    with patch("agent.recon.recon_orchestrator.run_passive_recon", fake_passive), patch("agent.recon.recon_orchestrator.discover_live_hosts", fake_live), patch("agent.recon.recon_orchestrator.discover_ports", fake_ports), patch("agent.recon.recon_orchestrator.run_web_recon", fake_web), patch("agent.recon.recon_orchestrator.run_katana", fake_katana), patch("agent.recon.recon_orchestrator.capture_screenshots", fake_screenshots):
        return run_recon_v2(config(assessment), target)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        domain = run_case("https://example.com/#/ignored", "Pre-Launch Black Box Testing")
        check(domain["target"]["normalized_url"] == "https://example.com", "domain fragment stripped")
        check(Path("reports/recon_report.html").exists(), "domain recon report generated")

    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        local = run_case("http://localhost:3000/#/", "Local Lab / Training")
        check(local["target"]["normalized_url"] == "http://localhost:3000", "localhost port preserved")
        check(local["subdomain_discovery_status"] == "skipped", "localhost skips subdomain discovery")

    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        ip = run_case("http://192.168.56.20", "Local Lab / Training")
        check(ip["target"]["target_kind"] == "ip", "IP target classified")
        check(ip["scope"]["allowed_hosts"] == ["192.168.56.20"], "IP direct scope")

    print("recon_workflow tests passed")


if __name__ == "__main__":
    main()
