from __future__ import annotations

from pathlib import Path

from agent.core.target_normalizer import normalize_target
from agent.recon.attack_surface_mapper import build_attack_surface
from agent.recon.dns_validator import validate_dns
from agent.recon.endpoint_inventory import build_important_endpoints
from agent.recon.host_discovery import discover_live_hosts
from agent.recon.katana_runner import run_katana
from agent.recon.passive_recon import run_passive_recon
from agent.recon.port_discovery import discover_ports
from agent.recon.recon_progress import init_progress_log, log_step
from agent.recon.screenshot_evidence import capture_screenshots
from agent.recon.subdomain_discovery_multi import discover_subdomains_multi
from agent.recon.tool_availability import check_tool_availability
from agent.recon.web_recon import run_web_recon
from agent.report.json_writer import read_json, write_json
from agent.report.recon_html_report import generate_recon_report

RECON_STAGES = [
    "Scope Definition",
    "Target Normalization",
    "Passive Recon",
    "Subdomain Discovery",
    "DNS Record Collection",
    "Host Discovery / HTTP Probing",
    "Port Discovery",
    "Service Enumeration",
    "Web Reconnaissance",
    "Technology Fingerprinting",
    "Security Header Review",
    "WAF/CDN Detection",
    "Screenshot / Evidence Collection",
    "Attack Surface Mapping",
    "Recon HTML Report Generation",
]


def _assessment_type(config: dict[str, object]) -> str:
    assessment = config.get("assessment", {}) if isinstance(config.get("assessment"), dict) else {}
    return str(assessment.get("type") or assessment.get("profile") or "Pre-Launch Black Box Testing")


def _authorized(config: dict[str, object]) -> bool:
    assessment = config.get("assessment", {}) if isinstance(config.get("assessment"), dict) else {}
    return bool(assessment.get("authorization_confirmed", False))


def _status_template() -> list[dict[str, str]]:
    return [{"stage": stage, "status": "Pending", "note": ""} for stage in RECON_STAGES]


def _mark(status: list[dict[str, str]], stage: str, value: str, note: str = "") -> None:
    for item in status:
        if item["stage"] == stage:
            item["status"] = value
            item["note"] = note
            break
    write_json("outputs/recon/recon_status.json", status)
    log_step(stage, value.lower(), note or value)


def _sync_scope(normalized: object, live_hosts: list[dict[str, object]], mode: str) -> dict[str, object]:
    allowed_hosts = sorted({str(item.get("hostname", "")).lower() for item in live_hosts if item.get("hostname")})
    allowed_urls = [str(item.get("url")) for item in live_hosts if item.get("url")]
    if not allowed_hosts:
        allowed_hosts = [normalized.hostname]
        allowed_urls = [normalized.normalized_url]
    scope = {
        "root_domain": normalized.registered_domain,
        "mode": mode,
        "allowed_hosts": allowed_hosts,
        "allowed_urls": allowed_urls,
        "source_files": ["outputs/recon/discovered_subdomains.json", "outputs/recon/live_hosts.json"],
    }
    write_json("outputs/dynamic_allowed_hosts.json", scope)
    return scope


def _write_domains(normalized: object) -> None:
    Path("outputs/recon").mkdir(parents=True, exist_ok=True)
    Path("outputs/recon/domains.txt").write_text(normalized.registered_domain + "\n", encoding="utf-8")


def _annotate_subdomains(live_hosts: list[dict[str, object]], dns_validated: list[dict[str, object]]) -> None:
    live_by_host = {str(item.get("hostname")): item for item in live_hosts}
    dns_by_host = {str(item.get("hostname")): item for item in dns_validated}
    subdomains = read_json("outputs/recon/discovered_subdomains.json", default=[]) or []
    for item in subdomains:
        if not isinstance(item, dict):
            continue
        live = live_by_host.get(str(item.get("hostname")))
        item["alive"] = bool(live)
        item["url"] = live.get("url", "") if live else ""
        item["status_code"] = live.get("status_code", "") if live else ""
        dns = dns_by_host.get(str(item.get("hostname")), {})
        item["resolved"] = bool(dns.get("resolved"))
        item["record_types_found"] = dns.get("record_types_found", [])
    write_json("outputs/recon/discovered_subdomains.json", subdomains)


def run_recon_v2(config: dict[str, object], target_url: str) -> dict[str, object]:
    if not _authorized(config):
        raise PermissionError("Authorization must be confirmed before running Recon v2.")

    output_dir = "outputs/recon"
    Path(f"{output_dir}/screenshots").mkdir(parents=True, exist_ok=True)
    init_progress_log()
    write_json(f"{output_dir}/tool_run_log.json", [])
    status = _status_template()
    check_tool_availability()
    assessment_type = _assessment_type(config)
    log_step("Normalisasi Target", "running", "Normalisasi target dimulai.")
    normalized = normalize_target(target_url, assessment_type)
    write_json("outputs/target_normalized.json", normalized.to_dict())
    write_json(f"{output_dir}/target_normalized.json", normalized.to_dict())
    _write_domains(normalized)
    _mark(status, "Scope Definition", "Done", "Authorized dynamic scope initialized.")
    _mark(status, "Target Normalization", "Done", normalized.normalized_url)

    log_step("Passive Recon", "running", "Passive recon dimulai.")
    passive = run_passive_recon(config, normalized.registered_domain, output_dir)
    _mark(status, "Passive Recon", "Done")
    _mark(status, "DNS Record Collection", "Done", f"{passive.get('dns_records', 0)} records.")

    subdomains = discover_subdomains_multi(config, normalized, output_dir)
    write_json("outputs/discovered_subdomains.json", subdomains)
    _mark(status, "Subdomain Discovery", "Skipped" if not normalized.subfinder_allowed else "Done", "Direct target scope." if not normalized.subfinder_allowed else f"{len(subdomains)} host(s).")

    dns_validated = validate_dns(f"{output_dir}/subdomains.txt", f"{output_dir}/dns_validated_hosts.json")
    _mark(status, "DNS Record Collection", "Done", f"{len(dns_validated)} host candidate(s) validated.")

    live_hosts = discover_live_hosts(config, normalized, output_dir)
    _annotate_subdomains(live_hosts, dns_validated)
    _mark(status, "Host Discovery / HTTP Probing", "Done", f"{len(live_hosts)} live host(s).")

    scope = _sync_scope(normalized, live_hosts, "direct_scope" if normalized.direct_scope else "dynamic_subdomain_recon")
    port_result = discover_ports(config, [str(item.get("hostname")) for item in live_hosts if item.get("hostname")], normalized, output_dir)
    _mark(status, "Port Discovery", "Done" if port_result["open_ports"] else "Skipped or No Open Ports")
    _mark(status, "Service Enumeration", "Done" if port_result["services"] else "Skipped or No Services")

    web = run_web_recon(config, live_hosts, output_dir)
    _mark(status, "Web Reconnaissance", "Done")
    _mark(status, "Technology Fingerprinting", "Done", f"{len(web['technologies'])} host(s).")
    _mark(status, "Security Header Review", "Done")
    _mark(status, "WAF/CDN Detection", "Done", f"{len(web['waf_cdn'])} indicator(s).")

    scan = config.get("scan", {}) if isinstance(config.get("scan"), dict) else {}
    tools = config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}
    log_step("Crawling Endpoint", "running", "Crawling endpoint dimulai.")
    endpoints = run_katana(scope["allowed_urls"], scope["allowed_hosts"], int(scan.get("max_urls_per_host", 200)), str(tools.get("katana", "katana")), f"{output_dir}/endpoints.json")
    write_json("outputs/endpoints.json", endpoints)
    important = build_important_endpoints(endpoints, f"{output_dir}/important_endpoints.json")
    log_step("Crawling Endpoint", "done", "Crawling endpoint selesai.", {"endpoints": len(endpoints), "important": len(important)})

    log_step("Screenshot/Evidence", "running", "Pengambilan screenshot/evidence dimulai.")
    screenshots = capture_screenshots(live_hosts, scope["allowed_hosts"], f"{output_dir}/screenshots")
    _mark(status, "Screenshot / Evidence Collection", "Done" if screenshots else "Skipped or No Evidence")

    log_step("Pemetaan Attack Surface", "running", "Pemetaan attack surface dimulai.")
    attack_surface = build_attack_surface(f"{output_dir}/attack_surface.json")
    _mark(status, "Attack Surface Mapping", "Done")

    source_breakdown = read_json(f"{output_dir}/subdomains_by_source.json", default={}) or {}
    tool_runs = read_json(f"{output_dir}/tool_run_log.json", default=[]) or []
    summary = {
        "target": normalized.to_dict(),
        "assessment_type": assessment_type,
        "methodology": "Black Box Recon",
        "scope": scope,
        "passive_recon": passive,
        "subdomain_discovery_status": "skipped" if not normalized.subfinder_allowed else "collected",
        "total_subdomains": len(read_json(f"{output_dir}/discovered_subdomains.json", default=[]) or []),
        "total_live_hosts": len(live_hosts),
        "total_open_ports": len(port_result["open_ports"]),
        "total_services": len(port_result["services"]),
        "total_web_technologies": sum(len(item.get("detected", [])) for item in web["technologies"] if isinstance(item, dict)),
        "total_important_endpoints": len(important),
        "total_attack_surface_categories": len(attack_surface),
        "subdomain_source_counts": {source: len(values) for source, values in source_breakdown.items() if isinstance(values, list)},
        "dns_validation": {
            "total_candidates": len(dns_validated),
            "resolved": sum(1 for item in dns_validated if item.get("resolved")),
            "unresolved": sum(1 for item in dns_validated if not item.get("resolved")),
        },
        "http_probe_summary": read_json(f"{output_dir}/http_probe_summary.json", default={}) or {},
        "tool_runs": tool_runs,
        "status": status,
    }
    log_step("Pembuatan Laporan Recon HTML", "running", "Pembuatan laporan recon HTML dimulai.")
    report = generate_recon_report(summary, "reports/recon_report.html")
    summary["reports"] = report
    write_json(f"{output_dir}/recon_summary.json", summary)
    _mark(status, "Recon HTML Report Generation", "Done", "reports/recon_report.html")
    summary["status"] = read_json(f"{output_dir}/recon_status.json", default=status) or status
    write_json(f"{output_dir}/recon_summary.json", summary)
    return summary
