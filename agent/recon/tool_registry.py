from __future__ import annotations

from typing import Any


TOOL_REGISTRY: list[dict[str, Any]] = [
    {"id": "whois", "display_name": "WHOIS", "category": "Passive Recon", "default_quick": False, "default_standard": False, "default_full": True, "requires": ["whois"], "description": "Collect WHOIS registration metadata.", "runtime": "10-60 detik", "output": "outputs/recon/whois.json"},
    {"id": "dns_records", "display_name": "DNS Records", "category": "DNS", "default_quick": True, "default_standard": True, "default_full": True, "requires": ["dig"], "description": "Collect standard DNS records.", "runtime": "5-30 detik", "output": "outputs/recon/dns_records.json"},
    {"id": "subfinder", "display_name": "Subfinder", "category": "Subdomain Discovery", "default_quick": True, "default_standard": True, "default_full": True, "requires": ["subfinder"], "description": "Passive subdomain discovery.", "runtime": "30-120 detik", "output": "outputs/recon/subdomains_by_source.json"},
    {"id": "amass_passive", "display_name": "Amass Passive", "category": "Subdomain Discovery", "default_quick": False, "default_standard": True, "default_full": True, "requires": ["amass"], "description": "Passive amass enumeration.", "runtime": "1-5 menit", "output": "outputs/recon/raw/amass_passive.txt"},
    {"id": "assetfinder", "display_name": "Assetfinder", "category": "Subdomain Discovery", "default_quick": False, "default_standard": True, "default_full": True, "requires": ["assetfinder"], "description": "Passive asset discovery.", "runtime": "30-90 detik", "output": "outputs/recon/raw/assetfinder.txt"},
    {"id": "certificate_transparency", "display_name": "Certificate Transparency", "category": "Subdomain Discovery", "default_quick": False, "default_standard": True, "default_full": True, "requires": [], "description": "Collect subdomains from certificate transparency logs.", "runtime": "10-60 detik", "output": "outputs/recon/raw/ct_subdomains.txt"},
    {"id": "dnsx", "display_name": "DNSx", "category": "DNS", "default_quick": True, "default_standard": True, "default_full": True, "requires": ["dnsx"], "description": "Validate discovered hostnames with DNS.", "runtime": "30-120 detik", "output": "outputs/recon/dns_validated_hosts.json"},
    {"id": "httpx", "display_name": "HTTPx", "category": "Web Discovery", "default_quick": True, "default_standard": True, "default_full": True, "requires": ["httpx"], "description": "Discover live HTTP services.", "runtime": "30-180 detik", "output": "outputs/recon/live_hosts.json"},
    {"id": "nmap_fast", "display_name": "Nmap Fast Safe Scan", "category": "Network", "default_quick": False, "default_standard": False, "default_full": True, "requires": ["nmap"], "description": "Run safe top-port discovery.", "runtime": "1-5 menit", "output": "outputs/recon/open_ports.json"},
    {"id": "whatweb", "display_name": "WhatWeb", "category": "Fingerprinting", "default_quick": True, "default_standard": True, "default_full": True, "requires": ["whatweb"], "description": "Fingerprint visible web technologies.", "runtime": "30-180 detik", "output": "outputs/recon/technologies.json"},
    {"id": "waf_cdn", "display_name": "WAF/CDN Detection", "category": "Fingerprinting", "default_quick": True, "default_standard": True, "default_full": True, "requires": [], "description": "Detect passive WAF/CDN indicators.", "runtime": "5-30 detik", "output": "outputs/recon/waf_cdn.json"},
    {"id": "security_headers", "display_name": "Security Header Review", "category": "Fingerprinting", "default_quick": True, "default_standard": True, "default_full": True, "requires": [], "description": "Review security headers and cookie attributes.", "runtime": "10-60 detik", "output": "outputs/recon/security_headers.json"},
    {"id": "katana", "display_name": "Katana Crawler", "category": "Crawling", "default_quick": True, "default_standard": True, "default_full": True, "requires": ["katana"], "description": "Crawl endpoints within authorized scope.", "runtime": "1-5 menit", "output": "outputs/recon/endpoints.json"},
    {"id": "zap_ensure_running", "display_name": "OWASP ZAP Ensure Running", "category": "OWASP ZAP", "default_quick": False, "default_standard": False, "default_full": False, "requires": ["zaproxy"], "description": "Ensure OWASP ZAP daemon is running.", "runtime": "5-60 detik", "output": "outputs/zap/zap_status.json"},
    {"id": "zap_traditional_spider", "display_name": "OWASP ZAP Traditional Spider", "category": "OWASP ZAP", "default_quick": False, "default_standard": True, "default_full": True, "requires": ["zaproxy"], "description": "Crawl target with OWASP ZAP traditional spider.", "runtime": "1-5 menit", "output": "outputs/zap/zap_urls.json"},
    {"id": "zap_ajax_spider", "display_name": "OWASP ZAP AJAX Spider", "category": "OWASP ZAP", "default_quick": False, "default_standard": False, "default_full": True, "requires": ["zaproxy"], "description": "Crawl target with OWASP ZAP AJAX spider.", "runtime": "2-10 menit", "output": "outputs/zap/zap_urls.json"},
    {"id": "zap_passive_scan", "display_name": "OWASP ZAP Passive Scan", "category": "OWASP ZAP", "default_quick": False, "default_standard": True, "default_full": True, "requires": ["zaproxy"], "description": "Collect OWASP ZAP passive alerts from observed traffic.", "runtime": "30-180 detik", "output": "outputs/zap/zap_passive_alerts.json"},
    {"id": "nuclei_safe", "display_name": "Nuclei Safe Templates", "category": "Scanner", "default_quick": False, "default_standard": False, "default_full": True, "requires": ["nuclei"], "description": "Run safe nuclei templates only.", "runtime": "1-5 menit", "output": "outputs/nuclei/nuclei_results.json"},
    {"id": "screenshot_evidence", "display_name": "Screenshot Evidence", "category": "Evidence", "default_quick": False, "default_standard": False, "default_full": True, "requires": [], "description": "Capture visual evidence for live hosts.", "runtime": "1-4 menit", "output": "outputs/recon/screenshot_index.json"},
    {"id": "attack_surface_mapping", "display_name": "Attack Surface Mapping", "category": "Analysis", "default_quick": False, "default_standard": True, "default_full": True, "requires": [], "description": "Map assets, services, technologies, and endpoints.", "runtime": "5-30 detik", "output": "outputs/recon/attack_surface.json"},
    {"id": "recon_report_generation", "display_name": "Recon Report Generation", "category": "Report", "default_quick": False, "default_standard": False, "default_full": True, "requires": [], "description": "Generate Indonesian reconnaissance report.", "runtime": "5-30 detik", "output": "reports/recon_report.html"},
]


MODE_KEYS = {"Quick Recon": "default_quick", "Standard Recon": "default_standard", "Full Recon": "default_full"}

ALIASES = {
    item["display_name"]: item["id"] for item in TOOL_REGISTRY
} | {
    "Katana light crawl": "katana",
    "Katana": "katana",
    "OWASP ZAP Traditional Spider light": "zap_traditional_spider",
    "Technology Fingerprint": "whatweb",
}


def canonical_tool_id(value: str) -> str:
    return ALIASES.get(value, value)


def auto_select_dependencies(tool_ids: list[str] | set[str]) -> list[str]:
    selected = {canonical_tool_id(str(tool_id)) for tool_id in tool_ids}
    if any(tool_id.startswith("zap_") and tool_id != "zap_ensure_running" for tool_id in selected):
        selected.add("zap_ensure_running")
    return [item["id"] for item in TOOL_REGISTRY if item["id"] in selected]


def default_tool_ids(recon_mode: str) -> list[str]:
    key = MODE_KEYS.get(recon_mode, "default_standard")
    return auto_select_dependencies([item["id"] for item in TOOL_REGISTRY if item.get(key)])


def registry_by_id() -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in TOOL_REGISTRY}
