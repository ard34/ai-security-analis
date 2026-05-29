from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.report.html_dashboard_generator import generate_dashboard
from agent.report.json_writer import write_json
from agent.report.recon_html_report import generate_recon_report


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def seed_common() -> None:
    write_json("outputs/recon/live_hosts.json", [{"hostname": "app.example.com", "url": "https://app.example.com", "status_code": 200, "title": "App", "webserver": "nginx", "technologies": ["React"]}])
    write_json("outputs/recon/dns_records.json", [{"type": "A", "name": "example.com", "value": "192.0.2.10", "ttl": 300}])
    write_json("outputs/recon/discovered_subdomains.json", [{"hostname": "app.example.com", "source": "target_input", "alive": True, "url": "https://app.example.com", "status_code": 200}])
    write_json("outputs/recon/open_ports.json", [{"host": "app.example.com", "port": 443, "protocol": "tcp", "service": "https"}])
    write_json("outputs/recon/services.json", [{"host": "app.example.com", "port": 443, "protocol": "tcp", "service": "https", "product": "nginx", "version": ""}])
    write_json("outputs/recon/technologies.json", [{"host": "app.example.com", "detected": [{"technology": "React"}, {"technology": "nginx"}]}])
    write_json("outputs/recon/waf_cdn.json", [{"host": "app.example.com", "provider": "Cloudflare", "method": "passive_headers", "bypass_attempted": False}])
    write_json("outputs/recon/security_headers.json", [{"host": "app.example.com", "missing_csp": True, "missing_hsts": False, "missing_x_frame_options": False, "missing_x_content_type_options": False, "cookie_issues": [], "cors_notes": "", "issue_count": 1}])
    write_json("outputs/recon/important_endpoints.json", [{"url": "https://app.example.com/login", "hostname": "app.example.com", "category": "auth"}])
    write_json("outputs/recon/attack_surface.json", [{"category": "Authentication Surfaces", "assets": [], "risk_hints": ["Auth review"], "recommended_manual_checks": ["Validate login"]}])
    write_json("outputs/recon/screenshot_index.json", {"status": "skipped", "screenshots": []})
    write_json("outputs/live_hosts.json", [{"hostname": "app.example.com", "url": "https://app.example.com", "status_code": 200, "title": "App", "webserver": "nginx", "tech": ["React"]}])
    write_json("outputs/endpoints.json", ["https://app.example.com/login"])
    write_json("outputs/security_headers.json", {"hosts": [], "findings": []})
    write_json("outputs/technology_fingerprint.json", {"hosts": [], "note": "test"})
    write_json("outputs/external_dependencies.json", [])
    write_json("outputs/auth_endpoints.json", ["https://app.example.com/login"])
    write_json("outputs/potential_findings.json", [{"title": "Potential IDOR/BOLA", "type": "BOLA/IDOR", "severity": "Medium", "confidence": "Medium", "url": "https://app.example.com/api/orders?id=1", "evidence": "Object identifier observed.", "recommendation": "Validate with two authorized test users.", "owasp_web": "A01 Broken Access Control", "owasp_api": "API1 Broken Object Property Level Authorization", "status": "Potential", "manual_validation_required": True, "testing_methodology": "black_box", "evidence_source": "Authenticated Browser Crawl", "black_box_limitations": "External evidence only.", "safe_testing_note": "Manual validation only."}])


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        seed_common()
        summary = {
            "target": {"input": "example.com", "normalized_url": "https://example.com", "target_kind": "domain", "registered_domain": "example.com"},
            "scope": {"mode": "dynamic_subdomain_recon", "allowed_hosts": ["app.example.com"]},
            "assessment_type": "Pre-Launch Black Box Testing",
            "passive_recon": {"whois": "skipped", "dns_records": 1, "ct_subdomains": 0, "public_repo_recon": "skipped"},
            "subdomain_discovery_status": "collected",
            "total_subdomains": 1,
            "total_live_hosts": 1,
            "total_open_ports": 1,
            "total_services": 1,
            "total_web_technologies": 2,
            "total_important_endpoints": 1,
            "total_attack_surface_categories": 1,
            "status": [],
        }
        write_json("outputs/recon/recon_summary.json", summary)
        generate_recon_report(summary)
        generate_dashboard({}, "https://example.com", "Pre-Launch Black Box Testing")
        recon = Path("reports/recon_report.html").read_text(encoding="utf-8")
        assessment = Path("reports/assessment.html").read_text(encoding="utf-8")
        for phrase in ["Ringkasan Eksekutif", "Target dan Ruang Lingkup", "Aktivitas Recon yang Dilakukan AI Agent", "Pemetaan Attack Surface", "Langkah Lanjutan"]:
            check(phrase in recon, f"recon contains {phrase}")
        for phrase in ["Ringkasan Eksekutif", "Metodologi Black Box", "Alert Potensi Bug", "Queue Validasi Manual"]:
            check(phrase in assessment, f"assessment contains {phrase}")
    print("indonesian_report_language tests passed")


if __name__ == "__main__":
    main()
