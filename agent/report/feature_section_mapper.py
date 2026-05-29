from __future__ import annotations

from pathlib import Path
from typing import Any

from agent.report.json_writer import read_json


def _lines(path: str) -> list[str]:
    file_path = Path(path)
    return [line.strip() for line in file_path.read_text(encoding="utf-8").splitlines() if line.strip()] if file_path.exists() else []


def _status(paths: list[str]) -> str:
    return "Selesai" if any(Path(path).exists() for path in paths) else "Dilewati"


def build_feature_sections() -> dict[str, dict[str, Any]]:
    subdomains_by_source = read_json("outputs/recon/subdomains_by_source.json", default={}) or {}
    tool_runs = read_json("outputs/recon/tool_run_log.json", default=[]) or []
    run_by_tool = {str(item.get("tool")): item for item in tool_runs if isinstance(item, dict)}

    def tool_section(title: str, key: str, files: list[str], table_data: list[Any] | None = None) -> dict[str, Any]:
        run = run_by_tool.get(key, {})
        return {
            "title": title,
            "status": run.get("status") or _status(files),
            "source_files": files,
            "summary_metrics": {"jumlah_hasil": len(table_data or []) if table_data is not None else sum(len(_lines(path)) for path in files)},
            "table_data": table_data if table_data is not None else _lines(files[0]) if files else [],
            "notes": run.get("reason", ""),
        }

    sections = {
        "subfinder": tool_section("Hasil Subfinder", "subfinder", ["outputs/recon/raw/subfinder.txt", "outputs/recon/subdomains_by_source.json"], subdomains_by_source.get("subfinder", [])),
        "amass": tool_section("Hasil Amass Passive", "amass", ["outputs/recon/raw/amass_passive.txt"], _lines("outputs/recon/raw/amass_passive.txt")),
        "assetfinder": tool_section("Hasil Assetfinder", "assetfinder", ["outputs/recon/raw/assetfinder.txt"], _lines("outputs/recon/raw/assetfinder.txt")),
        "certificate_transparency": tool_section("Hasil Certificate Transparency", "certificate_transparency", ["outputs/recon/raw/ct_subdomains.txt"], _lines("outputs/recon/raw/ct_subdomains.txt")),
        "dns": {"title": "Hasil DNS Records", "status": _status(["outputs/recon/dns_records.json"]), "source_files": ["outputs/recon/dns_records.json", "outputs/recon/dns_validated_hosts.json"], "summary_metrics": {"records": len(read_json("outputs/recon/dns_records.json", default=[]) or []), "validated": len(read_json("outputs/recon/dns_validated_hosts.json", default=[]) or [])}, "table_data": read_json("outputs/recon/dns_records.json", default=[]) or [], "notes": ""},
        "httpx": {"title": "Hasil HTTPx / Live Host Discovery", "status": _status(["outputs/recon/live_hosts.json"]), "source_files": ["outputs/recon/live_hosts.json", "outputs/recon/http_probe_summary.json"], "summary_metrics": read_json("outputs/recon/http_probe_summary.json", default={}) or {}, "table_data": read_json("outputs/recon/live_hosts.json", default=[]) or [], "notes": ""},
        "nmap": {"title": "Hasil Nmap / Port Discovery", "status": _status(["outputs/recon/open_ports.json"]), "source_files": ["outputs/recon/open_ports.json", "outputs/recon/services.json"], "summary_metrics": {"open_ports": len(read_json("outputs/recon/open_ports.json", default=[]) or [])}, "table_data": read_json("outputs/recon/services.json", default=[]) or [], "notes": run_by_tool.get("nmap", {}).get("reason", "")},
        "whatweb": {"title": "Hasil WhatWeb / Technology Fingerprint", "status": _status(["outputs/recon/technologies.json"]), "source_files": ["outputs/recon/technologies.json"], "summary_metrics": {"hosts": len(read_json("outputs/recon/technologies.json", default=[]) or [])}, "table_data": read_json("outputs/recon/technologies.json", default=[]) or [], "notes": run_by_tool.get("whatweb", {}).get("reason", "")},
        "waf_cdn": {"title": "Hasil WAF/CDN Detection", "status": _status(["outputs/recon/waf_cdn.json"]), "source_files": ["outputs/recon/waf_cdn.json"], "summary_metrics": {"indicators": len(read_json("outputs/recon/waf_cdn.json", default=[]) or [])}, "table_data": read_json("outputs/recon/waf_cdn.json", default=[]) or [], "notes": ""},
        "security_headers": {"title": "Hasil Security Header Review", "status": _status(["outputs/recon/security_headers.json"]), "source_files": ["outputs/recon/security_headers.json"], "summary_metrics": {"hosts": len(read_json("outputs/recon/security_headers.json", default=[]) or [])}, "table_data": read_json("outputs/recon/security_headers.json", default=[]) or [], "notes": ""},
        "zap": {"title": "Hasil OWASP ZAP", "status": _status(["outputs/zap/zap_passive_alerts.json"]), "source_files": ["outputs/zap/zap_spider_summary.json", "outputs/zap/zap_endpoint_inventory.json", "outputs/zap/zap_passive_alerts.json"], "summary_metrics": {"alerts": len(read_json("outputs/zap/zap_passive_alerts.json", default=[]) or [])}, "table_data": read_json("outputs/zap/zap_passive_alerts.json", default=[]) or [], "notes": ""},
        "potential_bugs": {"title": "Potential Bug Findings", "status": _status(["outputs/potential_findings.json"]), "source_files": ["outputs/alerts.json", "outputs/potential_findings.json", "outputs/manual_validation_queue.json"], "summary_metrics": {"findings": len(read_json("outputs/potential_findings.json", default=[]) or [])}, "table_data": read_json("outputs/potential_findings.json", default=[]) or [], "notes": ""},
        "attack_surface": {"title": "Pemetaan Attack Surface", "status": _status(["outputs/recon/attack_surface.json"]), "source_files": ["outputs/recon/attack_surface.json"], "summary_metrics": {"categories": len(read_json("outputs/recon/attack_surface.json", default=[]) or [])}, "table_data": read_json("outputs/recon/attack_surface.json", default=[]) or [], "notes": ""},
        "evidence": {"title": "Screenshot dan Evidence", "status": _status(["outputs/recon/screenshot_index.json"]), "source_files": ["outputs/recon/screenshots/", "outputs/recon/screenshot_index.json"], "summary_metrics": {"screenshots": len((read_json("outputs/recon/screenshot_index.json", default={}) or {}).get("screenshots", []))}, "table_data": (read_json("outputs/recon/screenshot_index.json", default={}) or {}).get("screenshots", []), "notes": ""},
    }
    return sections
