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
        write_json("outputs/recon/live_hosts.json", [{"hostname": "app.example.com", "url": "https://app.example.com", "status_code": 200, "title": "App", "webserver": "nginx", "technologies": ["React"]}])
        write_json("outputs/recon/dns_records.json", [{"type": "A", "name": "example.com", "value": "192.0.2.10", "ttl": 300}])
        write_json("outputs/recon/discovered_subdomains.json", [{"hostname": "app.example.com", "source": "target_input", "alive": True, "url": "https://app.example.com", "status_code": 200}])
        write_json("outputs/recon/open_ports.json", [{"host": "app.example.com", "port": 443, "protocol": "tcp", "service": "https"}])
        write_json("outputs/recon/services.json", [{"host": "app.example.com", "port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": ""}])
        write_json("outputs/recon/technologies.json", [{"host": "app.example.com", "detected": [{"technology": "React"}, {"technology": "nginx"}]}])
        write_json("outputs/recon/waf_cdn.json", [{"host": "app.example.com", "provider": "Cloudflare"}])
        write_json("outputs/recon/security_headers.json", [{"host": "app.example.com", "missing_csp": True, "missing_hsts": False, "missing_x_frame_options": False, "missing_x_content_type_options": False, "cookie_issues": [], "cors_notes": "", "issue_count": 1}])
        write_json("outputs/recon/important_endpoints.json", [{"url": "https://app.example.com/login", "hostname": "app.example.com", "category": "auth"}])
        write_json("outputs/recon/attack_surface.json", [{"category": "Authentication Surfaces", "assets": [], "risk_hints": ["Auth review"], "recommended_manual_checks": ["Validate login"]}])
        write_json("outputs/recon/screenshot_index.json", {"status": "skipped", "screenshots": []})

        summary = {
            "target": {"input": "example.com", "normalized_url": "https://example.com", "target_kind": "domain", "registered_domain": "example.com"},
            "scope": {"mode": "dynamic_subdomain_recon", "allowed_hosts": ["app.example.com"]},
            "assessment_type": "Pre-Launch Black Box Testing",
            "passive_recon": {"whois": "skipped", "dns_records": 1, "ct_subdomains": 0, "public_repo_recon": "skipped"},
            "subdomain_discovery_status": "collected",
        }
        result = generate_recon_report(summary)
        content = Path(result["html"]).read_text(encoding="utf-8")
        check("Laporan Reconnaissance" in content, "title present")
        for section in [
            "Ringkasan Eksekutif",
            "Target dan Ruang Lingkup",
            "Aktivitas Recon yang Dilakukan AI Agent",
            "Penemuan Subdomain",
            "Validasi DNS",
            "Host Aktif",
            "Port dan Layanan",
            "Teknologi yang Terdeteksi",
            "Deteksi WAF/CDN",
            "Pemeriksaan Security Header",
            "Endpoint Penting",
            "Pemetaan Attack Surface",
            "Screenshot dan Evidence",
            "Langkah Lanjutan",
        ]:
            check(section in content, f"{section} present")
    print("recon_report_generation tests passed")


if __name__ == "__main__":
    main()
