from __future__ import annotations

import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent.core.target_normalizer import NormalizedTarget, normalize_target
from agent.recon.attack_surface_mapper import build_attack_surface
from agent.core.scope_validator import is_same_registered_domain
from agent.recon.certificate_transparency import collect_ct_subdomains
from agent.recon.dns_records import collect_dns_records
from agent.recon.dns_validator import validate_dns
from agent.recon.endpoint_inventory import build_important_endpoints
from agent.recon.host_discovery import discover_live_hosts
from agent.recon.katana_runner import run_katana
from agent.recon.port_discovery import discover_ports
from agent.recon.recon_progress import init_progress_log, log_step
from agent.recon.screenshot_evidence import capture_screenshots
from agent.recon.security_header_reviewer import review_security_headers
from agent.recon.subdomain_discovery_multi import _run_amass, _run_assetfinder, _run_subfinder
from agent.recon.tool_availability import check_tool_availability
from agent.recon.tool_registry import auto_select_dependencies, canonical_tool_id
from agent.recon.waf_cdn_detector import detect_waf_cdn
from agent.recon.web_fingerprint import fingerprint_web_hosts
from agent.integrations.zap_controller import ensure_zap_running
from agent.report.json_writer import read_json, write_json
from agent.report.recon_html_report import generate_recon_report
from agent.scanners.nuclei_safe_scan import run_nuclei_safe_scan
from agent.scanners.zap_spider import (
    collect_zap_alerts,
    collect_zap_messages,
    normalize_target_urls,
    run_ajax_spider,
    run_traditional_spider,
    wait_for_passive_scan,
)
from agent.traffic.endpoint_classifier import classify_endpoint
from agent.utils.command_runner import command_exists
from agent.utils.tool_runner import record_tool_skipped, run_tool


OUTPUT_DIR = Path("outputs/recon")
ZAP_DIR = Path("outputs/zap")

EXECUTION_ORDER = [
    "Target Normalization",
    "Scope Definition",
    "Tool Availability Check",
    "whois",
    "dns_records",
    "subfinder",
    "amass_passive",
    "assetfinder",
    "certificate_transparency",
    "Merge Subdomain Results",
    "dnsx",
    "httpx",
    "nmap_fast",
    "whatweb",
    "waf_cdn",
    "security_headers",
    "katana",
    "zap_ensure_running",
    "zap_traditional_spider",
    "zap_ajax_spider",
    "zap_passive_scan",
    "nuclei_safe",
    "screenshot_evidence",
    "Endpoint Classification",
    "attack_surface_mapping",
    "recon_report_generation",
]

COMMAND_TOOLS = {
    "whois": "whois",
    "subfinder": "subfinder",
    "amass_passive": "amass",
    "assetfinder": "assetfinder",
    "dnsx": "dnsx",
    "httpx": "httpx",
    "nmap_fast": "nmap",
    "whatweb": "whatweb",
    "katana": "katana",
    "nuclei_safe": "nuclei",
}

ALWAYS_RUN = {"Target Normalization", "Scope Definition", "Tool Availability Check", "Merge Subdomain Results", "Endpoint Classification"}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _canonical(tool: str) -> str:
    return canonical_tool_id(tool)


def build_execution_plan(selected_tools: list[str]) -> list[dict[str, str]]:
    selected = set(auto_select_dependencies([_canonical(tool) for tool in selected_tools]))
    plan = []
    for step in EXECUTION_ORDER:
        planned = step in ALWAYS_RUN or step in selected
        plan.append({"step": step, "status": "Pending" if planned else "Skipped", "reason": "" if planned else "User did not select this tool"})
    return plan


def _append_tool_run(entry: dict[str, Any]) -> None:
    runs = read_json(OUTPUT_DIR / "tool_run_log.json", default=[]) or []
    runs.append(entry)
    write_json(OUTPUT_DIR / "tool_run_log.json", runs)


def _tool_entry(tool: str, status: str, started: str, result_count: int = 0, reason: str = "", output_path: str = "") -> dict[str, Any]:
    return {
        "tool": tool,
        "command": [],
        "target": "",
        "status": status,
        "started_at": started,
        "finished_at": _now(),
        "duration_seconds": 0,
        "exit_code": None,
        "stdout_path": output_path,
        "stderr_path": "",
        "result_count": result_count,
        "reason": reason,
    }


def _count_file(path: str | Path) -> int:
    value = read_json(path, default=[])
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return sum(len(v) for v in value.values() if isinstance(v, list))
    return 0


def _write_scope(normalized: NormalizedTarget, live_hosts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    hosts = sorted({str(item.get("hostname")) for item in live_hosts or [] if isinstance(item, dict) and item.get("hostname")})
    urls = [str(item.get("url")) for item in live_hosts or [] if isinstance(item, dict) and item.get("url")]
    if not hosts:
        hosts = [normalized.registered_domain]
        if normalized.hostname not in hosts:
            hosts.append(normalized.hostname)
    if not urls:
        urls = [normalized.normalized_url]
    scope = {
        "root_domain": normalized.registered_domain,
        "mode": "dynamic_subdomain_recon" if normalized.subfinder_allowed else "direct_scope",
        "allowed_hosts": hosts,
        "allowed_urls": urls,
        "source_files": ["outputs/recon/subdomains.txt", "outputs/recon/live_hosts.json"],
    }
    write_json("outputs/dynamic_allowed_hosts.json", scope)
    return scope


def _write_empty_outputs() -> None:
    for path, default in [
        ("outputs/recon/whois.json", {}),
        ("outputs/recon/dns_records.json", []),
        ("outputs/recon/subdomains_by_source.json", {}),
        ("outputs/recon/subdomains_all_sources.json", []),
        ("outputs/recon/rejected_subdomain_candidates.json", []),
        ("outputs/recon/dns_validated_hosts.json", []),
        ("outputs/recon/live_hosts.json", []),
        ("outputs/recon/http_probe_summary.json", {}),
        ("outputs/recon/open_ports.json", []),
        ("outputs/recon/services.json", []),
        ("outputs/recon/whatweb_results.json", []),
        ("outputs/recon/technologies.json", []),
        ("outputs/recon/waf_cdn.json", []),
        ("outputs/recon/security_headers.json", []),
        ("outputs/recon/endpoints.json", []),
        ("outputs/recon/screenshot_index.json", []),
        ("outputs/recon/attack_surface.json", []),
        ("outputs/nuclei/nuclei_results.json", []),
        ("outputs/zap/zap_status.json", {}),
        ("outputs/zap/zap_urls.json", []),
        ("outputs/zap/zap_messages.json", []),
        ("outputs/zap/zap_alerts_raw.json", []),
        ("outputs/zap/zap_passive_alerts.json", []),
        ("outputs/zap/zap_endpoint_inventory.json", []),
        ("outputs/zap/zap_spider_summary.json", {}),
    ]:
        if not Path(path).exists():
            write_json(path, default)


def _load_by_source(normalized: NormalizedTarget) -> dict[str, list[str]]:
    existing = read_json(OUTPUT_DIR / "subdomains_by_source.json", default={}) or {}
    by_source = existing if isinstance(existing, dict) else {}
    by_source.setdefault("target_input", sorted({normalized.registered_domain, normalized.hostname}))
    return {str(key): [str(item) for item in value] for key, value in by_source.items() if isinstance(value, list)}


def _write_merged_subdomains(normalized: NormalizedTarget, by_source: dict[str, list[str]]) -> list[dict[str, Any]]:
    write_json(OUTPUT_DIR / "subdomains_by_source.json", by_source)
    accepted: dict[str, set[str]] = {}
    rejected = []
    for source, hosts in by_source.items():
        for host in sorted({str(host).lower().strip("*.").strip(".") for host in hosts if host}):
            same_registered = host == normalized.registered_domain or host.endswith("." + normalized.registered_domain)
            if not same_registered and "." in host and "." in normalized.registered_domain:
                same_registered = is_same_registered_domain(host, normalized.registered_domain)
            if same_registered:
                accepted.setdefault(host, set()).add(source)
            else:
                rejected.append({"hostname": host, "source": source, "root_domain": normalized.registered_domain, "accepted": False, "reject_reason": "outside_registered_domain"})
    items = [
        {"hostname": host, "sources": sorted(sources), "source": ", ".join(sorted(sources)), "accepted": True, "root_domain": normalized.registered_domain}
        for host, sources in sorted(accepted.items())
    ]
    write_json(OUTPUT_DIR / "subdomains_all_sources.json", items)
    write_json(OUTPUT_DIR / "rejected_subdomain_candidates.json", rejected)
    write_json(OUTPUT_DIR / "discovered_subdomains.json", items)
    Path(OUTPUT_DIR / "subdomains.txt").write_text("\n".join(item["hostname"] for item in items) + "\n", encoding="utf-8")
    return items


def _source_discovery_step(normalized: NormalizedTarget, source: str) -> list[dict[str, Any]]:
    by_source = _load_by_source(normalized)
    root = normalized.registered_domain
    if source == "Subfinder":
        by_source["subfinder"] = _run_subfinder(root)
    elif source == "Amass Passive":
        by_source["amass"] = _run_amass(root)
    elif source == "Assetfinder":
        by_source["assetfinder"] = _run_assetfinder(root)
    elif source == "Certificate Transparency":
        ct = collect_ct_subdomains(root, str(OUTPUT_DIR / "ct_subdomains.json"))
        hosts = [str(item.get("hostname")) for item in ct if isinstance(item, dict) and item.get("hostname")]
        by_source["certificate_transparency"] = hosts
        Path(OUTPUT_DIR / "raw/ct_subdomains.txt").write_text("\n".join(sorted(set(hosts))) + ("\n" if hosts else ""), encoding="utf-8")
    return _write_merged_subdomains(normalized, by_source)


def _run_whois(domain: str) -> dict[str, Any]:
    if not command_exists("whois"):
        record_tool_skipped("whois", "Tool not installed", domain)
        write_json(OUTPUT_DIR / "whois.json", {"domain": domain, "status": "Skipped", "reason": "Tool not installed"})
        return {"status": "Skipped", "count": 0}
    result = run_tool(["whois", domain], 60, "whois", target=domain)
    write_json(OUTPUT_DIR / "whois.json", {"domain": domain, "status": result.get("status"), "raw": result.get("stdout", "")[:20000], "reason": result.get("reason", "")})
    return {"status": str(result.get("status", "Done")), "count": 1 if result.get("stdout") else 0, "reason": result.get("reason", "")}


def _record_step(status_rows: list[dict[str, Any]], step: str, status: str, message: str, count: int = 0, reason: str = "", output_path: str = "") -> None:
    for row in status_rows:
        if row["step"] == step:
            row.update({"status": status, "reason": reason, "count": count, "output_path": output_path, "finished_at": _now()})
            break
    write_json(OUTPUT_DIR / "recon_status.json", status_rows)
    log_step(step, status.lower(), message, {"count": count, "reason": reason, "output_path": output_path})


def _run_step(
    status_rows: list[dict[str, Any]],
    step: str,
    selected: set[str],
    func: Callable[[], tuple[str, int, str, str]],
) -> None:
    started = _now()
    if step not in ALWAYS_RUN and step not in selected:
        reason = "User did not select this tool"
        _record_step(status_rows, step, "Skipped", reason, reason=reason)
        _append_tool_run(_tool_entry(step, "Skipped", started, reason=reason))
        return
    command = COMMAND_TOOLS.get(step)
    if command and not command_exists(command):
        reason = "Tool not installed"
        _record_step(status_rows, step, "Skipped", reason, reason=reason)
        _append_tool_run(_tool_entry(step, "Skipped", started, reason=reason))
        return
    _record_step(status_rows, step, "Running", f"{step} running")
    try:
        status, count, reason, output_path = func()
    except TimeoutError as exc:
        status, count, reason, output_path = "Timeout", 0, str(exc), ""
    except Exception as exc:
        status, count, reason, output_path = "Failed", 0, str(exc)[:300], ""
    _record_step(status_rows, step, status, f"{step}: {status}", count=count, reason=reason, output_path=output_path)
    if not any(isinstance(item, dict) and item.get("tool") == step and item.get("started_at") >= started for item in (read_json(OUTPUT_DIR / "tool_run_log.json", default=[]) or [])):
        _append_tool_run(_tool_entry(step, status, started, count, reason, output_path))


def run_selected_recon_tools(config: dict[str, Any], target_domain: str, selected_tools: list[str], recon_mode: str) -> dict[str, Any]:
    started_at = _now()
    started_clock = time.monotonic()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "raw").mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "screenshots").mkdir(parents=True, exist_ok=True)
    ZAP_DIR.mkdir(parents=True, exist_ok=True)
    Path("outputs/nuclei").mkdir(parents=True, exist_ok=True)
    Path("reports").mkdir(parents=True, exist_ok=True)
    init_progress_log()
    write_json(OUTPUT_DIR / "tool_run_log.json", [])
    _write_empty_outputs()

    selected = set(auto_select_dependencies([_canonical(tool) for tool in selected_tools]))
    selected_tool_ids = [tool_id for tool_id in EXECUTION_ORDER if tool_id in selected]
    write_json(OUTPUT_DIR / "selected_tools.json", {"target_domain": target_domain, "recon_mode": recon_mode, "selected_tool_ids": selected_tool_ids, "started_at": started_at})
    log_step("Selected Tools", "done", "Selected tools: " + ", ".join(selected_tool_ids), {"selected_tool_ids": selected_tool_ids})
    status_rows = build_execution_plan(list(selected))
    write_json(OUTPUT_DIR / "recon_status.json", status_rows)

    state: dict[str, Any] = {"normalized": None, "scope": {}, "live_hosts": []}

    def target_normalization() -> tuple[str, int, str, str]:
        normalized = normalize_target(target_domain, "Pre-Launch Black Box Testing")
        state["normalized"] = normalized
        write_json("outputs/target_normalized.json", normalized.to_dict())
        write_json(OUTPUT_DIR / "target_normalized.json", normalized.to_dict())
        Path(OUTPUT_DIR / "domains.txt").write_text(normalized.registered_domain + "\n", encoding="utf-8")
        return "Done", 1, "", "outputs/recon/target_normalized.json"

    def scope_definition() -> tuple[str, int, str, str]:
        normalized = state["normalized"]
        state["scope"] = _write_scope(normalized)
        return "Done", len(state["scope"].get("allowed_hosts", [])), "", "outputs/dynamic_allowed_hosts.json"

    def availability() -> tuple[str, int, str, str]:
        results = check_tool_availability(str(OUTPUT_DIR / "tool_availability.json"))
        return "Done", len(results), "", "outputs/recon/tool_availability.json"

    def dns_records() -> tuple[str, int, str, str]:
        records = collect_dns_records(state["normalized"].registered_domain, str(OUTPUT_DIR / "dns_records.json"))
        return "Done", len(records), "", "outputs/recon/dns_records.json"

    def source_discovery(step_name: str) -> tuple[str, int, str, str]:
        items = _source_discovery_step(state["normalized"], step_name)
        return "Done", len(items), "", "outputs/recon/subdomains_by_source.json"

    def merge() -> tuple[str, int, str, str]:
        by_source = _load_by_source(state["normalized"])
        items = _write_merged_subdomains(state["normalized"], by_source)
        return "Done", len(items), "", "outputs/recon/subdomains_all_sources.json"

    def dnsx() -> tuple[str, int, str, str]:
        rows = validate_dns(str(OUTPUT_DIR / "subdomains.txt"), str(OUTPUT_DIR / "dns_validated_hosts.json"))
        return "Done", len(rows), "", "outputs/recon/dns_validated_hosts.json"

    def httpx() -> tuple[str, int, str, str]:
        live = discover_live_hosts(config, state["normalized"], str(OUTPUT_DIR))
        state["live_hosts"] = live
        state["scope"] = _write_scope(state["normalized"], live)
        return "Done", len(live), "", "outputs/recon/live_hosts.json"

    def nmap() -> tuple[str, int, str, str]:
        hosts = [str(item.get("hostname")) for item in state["live_hosts"] if isinstance(item, dict) and item.get("hostname")]
        result = discover_ports(config, hosts, state["normalized"], str(OUTPUT_DIR))
        return "Done", len(result.get("open_ports", [])), "", "outputs/recon/open_ports.json"

    def whatweb() -> tuple[str, int, str, str]:
        rows = fingerprint_web_hosts(state["live_hosts"], str((config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}).get("whatweb", "whatweb")), str(OUTPUT_DIR / "technologies.json"))
        write_json(OUTPUT_DIR / "whatweb_results.json", rows)
        return "Done", len(rows), "", "outputs/recon/technologies.json"

    def headers() -> tuple[str, int, str, str]:
        rows = review_security_headers(state["live_hosts"], str(OUTPUT_DIR / "security_headers.json"))
        return "Done", len(rows), "", "outputs/recon/security_headers.json"

    def waf() -> tuple[str, int, str, str]:
        rows = detect_waf_cdn(read_json(OUTPUT_DIR / "security_headers.json", default=[]) or [], read_json(OUTPUT_DIR / "technologies.json", default=[]) or [], str(OUTPUT_DIR / "waf_cdn.json"))
        return "Done", len(rows), "", "outputs/recon/waf_cdn.json"

    def katana() -> tuple[str, int, str, str]:
        scope = state.get("scope") or _write_scope(state["normalized"], state["live_hosts"])
        scan = config.get("scan", {}) if isinstance(config.get("scan"), dict) else {}
        tools = config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}
        endpoints = run_katana(scope.get("allowed_urls", []), scope.get("allowed_hosts", []), int(scan.get("max_urls_per_host", 80)), str(tools.get("katana", "katana")), str(OUTPUT_DIR / "endpoints.json"))
        raw = [str(item.get("url") or item) for item in endpoints if item]
        Path(OUTPUT_DIR / "raw/katana_urls.txt").write_text("\n".join(raw) + ("\n" if raw else ""), encoding="utf-8")
        build_important_endpoints(endpoints, str(OUTPUT_DIR / "important_endpoints.json"))
        return "Done", len(endpoints), "", "outputs/recon/endpoints.json"

    def _zap_targets() -> tuple[list[str], list[str]]:
        normalized = state["normalized"]
        live_hosts = state["live_hosts"] or read_json(OUTPUT_DIR / "live_hosts.json", default=[]) or []
        allowed_hosts = [str(item.get("hostname")) for item in live_hosts if isinstance(item, dict) and item.get("hostname")]
        if not allowed_hosts:
            allowed_hosts = [normalized.registered_domain, normalized.hostname]
        urls = normalize_target_urls(normalized.registered_domain, live_hosts if isinstance(live_hosts, list) else [])
        return urls, sorted(set(host for host in allowed_hosts if host))

    def zap_ensure() -> tuple[str, int, str, str]:
        log_step("ZAP daemon check", "running", "ZAP daemon check started")
        status = ensure_zap_running(config)
        zap_status = str(status.get("status", "Failed"))
        log_step("ZAP daemon check", zap_status.lower(), f"ZAP daemon {zap_status}", status)
        if zap_status == "Ready":
            return "Done", 1, "", "outputs/zap/zap_status.json"
        if zap_status in {"Disabled", "Not Installed"}:
            return "Skipped", 0, str(status.get("message", zap_status)), "outputs/zap/zap_status.json"
        return "Failed", 0, str(status.get("message", zap_status)), "outputs/zap/zap_status.json"

    def zap_traditional() -> tuple[str, int, str, str]:
        status = ensure_zap_running(config)
        if status.get("status") in {"Disabled", "Not Installed"}:
            return "Skipped", 0, str(status.get("message", status.get("status"))), "outputs/zap/zap_status.json"
        if status.get("status") != "Ready":
            return "Failed", 0, str(status.get("message", "ZAP API not ready")), "outputs/zap/zap_status.json"
        urls, allowed_hosts = _zap_targets()
        if not urls:
            return "Skipped", 0, "No reachable target URL for ZAP spider.", "outputs/zap/zap_urls.json"
        for url in urls:
            log_step("ZAP Traditional Spider", "running", f"ZAP Traditional Spider started for {url}")
        result = run_traditional_spider(config, urls, allowed_hosts)
        collect_zap_messages(config, allowed_hosts)
        alerts = collect_zap_alerts(config, allowed_hosts=allowed_hosts)
        count = int(result.get("urls_count", 0) or 0)
        log_step("ZAP Traditional Spider", "done", f"ZAP Traditional Spider done: {count} URLs", {"alerts": len(alerts)})
        reason = "" if count else "Executed successfully; no results found."
        return "Done", count, reason, "outputs/zap/zap_urls.json"

    def zap_ajax() -> tuple[str, int, str, str]:
        status = ensure_zap_running(config)
        if status.get("status") in {"Disabled", "Not Installed"}:
            return "Skipped", 0, str(status.get("message", status.get("status"))), "outputs/zap/zap_status.json"
        if status.get("status") != "Ready":
            return "Failed", 0, str(status.get("message", "ZAP API not ready")), "outputs/zap/zap_status.json"
        urls, allowed_hosts = _zap_targets()
        if not urls:
            return "Skipped", 0, "No reachable target URL for ZAP spider.", "outputs/zap/zap_urls.json"
        result = run_ajax_spider(config, urls, allowed_hosts)
        collect_zap_messages(config, allowed_hosts)
        collect_zap_alerts(config, allowed_hosts=allowed_hosts)
        count = int(result.get("urls_count", 0) or 0)
        reason = "" if count else "Executed successfully; no results found."
        return "Done", count, reason, "outputs/zap/zap_urls.json"

    def zap_passive() -> tuple[str, int, str, str]:
        status = ensure_zap_running(config)
        if status.get("status") in {"Disabled", "Not Installed"}:
            return "Skipped", 0, str(status.get("message", status.get("status"))), "outputs/zap/zap_status.json"
        if status.get("status") != "Ready":
            return "Failed", 0, str(status.get("message", "ZAP API not ready")), "outputs/zap/zap_status.json"
        _urls, allowed_hosts = _zap_targets()
        wait_for_passive_scan(config, 30)
        alerts = collect_zap_alerts(config, allowed_hosts=allowed_hosts)
        collect_zap_messages(config, allowed_hosts)
        log_step("ZAP Passive Scan", "done", f"ZAP Passive Scan collected: {len(alerts)} alerts")
        reason = "" if alerts else "Executed successfully; no results found."
        return "Done", len(alerts), reason, "outputs/zap/zap_passive_alerts.json"

    def nuclei() -> tuple[str, int, str, str]:
        urls = [str(item.get("url")) for item in state["live_hosts"] if isinstance(item, dict) and item.get("url")]
        rows = run_nuclei_safe_scan(config, urls, "outputs/nuclei/nuclei_results.json")
        return "Done", len(rows), "", "outputs/nuclei/nuclei_results.json"

    def screenshots() -> tuple[str, int, str, str]:
        scope = state.get("scope") or {}
        rows = capture_screenshots(state["live_hosts"], scope.get("allowed_hosts", []), str(OUTPUT_DIR / "screenshots"))
        return "Done" if rows else "Skipped", len(rows), "" if rows else "No live hosts or screenshot engine unavailable", "outputs/recon/screenshot_index.json"

    def classify() -> tuple[str, int, str, str]:
        endpoints = read_json(OUTPUT_DIR / "endpoints.json", default=[]) or []
        rows = []
        for item in endpoints if isinstance(endpoints, list) else []:
            if isinstance(item, dict):
                item["classification"] = classify_endpoint(item)
                rows.append(item)
        write_json(OUTPUT_DIR / "endpoints.json", rows)
        return "Done", len(rows) if isinstance(rows, list) else 0, "", "outputs/recon/endpoints.json"

    def attack_surface() -> tuple[str, int, str, str]:
        rows = build_attack_surface(str(OUTPUT_DIR / "attack_surface.json"))
        return "Done", len(rows), "", "outputs/recon/attack_surface.json"

    def report() -> tuple[str, int, str, str]:
        summary = _summary(started_at, recon_mode, selected_tool_ids, status_rows, state)
        report_result = generate_recon_report(summary, "reports/recon_report.html")
        summary["reports"] = report_result
        write_json(OUTPUT_DIR / "recon_summary.json", summary)
        return "Done", 1, "", "reports/recon_report.html"

    handlers: dict[str, Callable[[], tuple[str, int, str, str]]] = {
        "Target Normalization": target_normalization,
        "Scope Definition": scope_definition,
        "Tool Availability Check": availability,
        "whois": lambda: (lambda result: (result["status"], result["count"], result.get("reason", ""), "outputs/recon/whois.json"))(_run_whois(state["normalized"].registered_domain)),
        "dns_records": dns_records,
        "subfinder": lambda: source_discovery("Subfinder"),
        "amass_passive": lambda: source_discovery("Amass Passive"),
        "assetfinder": lambda: source_discovery("Assetfinder"),
        "certificate_transparency": lambda: source_discovery("Certificate Transparency"),
        "Merge Subdomain Results": merge,
        "dnsx": dnsx,
        "httpx": httpx,
        "nmap_fast": nmap,
        "whatweb": whatweb,
        "waf_cdn": waf,
        "security_headers": headers,
        "katana": katana,
        "zap_ensure_running": zap_ensure,
        "zap_traditional_spider": zap_traditional,
        "zap_ajax_spider": zap_ajax,
        "zap_passive_scan": zap_passive,
        "nuclei_safe": nuclei,
        "screenshot_evidence": screenshots,
        "Endpoint Classification": classify,
        "attack_surface_mapping": attack_surface,
        "recon_report_generation": report,
    }

    for step in EXECUTION_ORDER:
        _run_step(status_rows, step, selected, handlers[step])

    summary = _summary(started_at, recon_mode, selected_tool_ids, status_rows, state)
    summary["duration_seconds"] = round(time.monotonic() - started_clock, 3)
    summary["run_status"] = "Failed" if any(row.get("status") == "Failed" for row in status_rows) else "Completed"
    write_json(OUTPUT_DIR / "recon_summary.json", summary)
    _append_scan_history(summary)
    return summary


def _summary(started_at: str, recon_mode: str, selected_tools: list[str], status_rows: list[dict[str, Any]], state: dict[str, Any]) -> dict[str, Any]:
    normalized = state.get("normalized")
    live_hosts = read_json(OUTPUT_DIR / "live_hosts.json", default=[]) or []
    ports = read_json(OUTPUT_DIR / "open_ports.json", default=[]) or []
    services = read_json(OUTPUT_DIR / "services.json", default=[]) or []
    technologies = read_json(OUTPUT_DIR / "technologies.json", default=[]) or []
    endpoints = read_json(OUTPUT_DIR / "endpoints.json", default=[]) or []
    attack_surface = read_json(OUTPUT_DIR / "attack_surface.json", default=[]) or []
    by_source = read_json(OUTPUT_DIR / "subdomains_by_source.json", default={}) or {}
    return {
        "target": normalized.to_dict() if normalized else {},
        "recon_mode": recon_mode,
        "selected_tools": selected_tools,
        "started_at": started_at,
        "finished_at": _now(),
        "methodology": "Black Box Recon",
        "scope": state.get("scope") or {},
        "run_status": "Running",
        "total_subdomains": _count_file(OUTPUT_DIR / "subdomains_all_sources.json"),
        "total_live_hosts": len(live_hosts),
        "total_open_ports": len(ports),
        "total_services": len(services),
        "total_web_technologies": len(technologies),
        "total_important_endpoints": len(endpoints),
        "total_attack_surface_categories": len(attack_surface),
        "subdomain_source_counts": {source: len(values) for source, values in by_source.items() if isinstance(values, list)} if isinstance(by_source, dict) else {},
        "tool_runs": read_json(OUTPUT_DIR / "tool_run_log.json", default=[]) or [],
        "status": status_rows,
    }


def _append_scan_history(summary: dict[str, Any]) -> None:
    history = read_json("outputs/scan_history.json", default=[]) or []
    target = summary.get("target", {}) if isinstance(summary.get("target"), dict) else {}
    history.insert(
        0,
        {
            "target": target.get("registered_domain") or target.get("hostname") or "",
            "workspace": "Default Workspace",
            "mode": summary.get("recon_mode", ""),
            "selected_tools": summary.get("selected_tools", []),
            "status": summary.get("run_status", "Completed"),
            "started_at": summary.get("started_at", ""),
            "finished_at": summary.get("finished_at", ""),
            "duration_seconds": summary.get("duration_seconds", ""),
            "metrics": {
                "Live Hosts": summary.get("total_live_hosts", 0),
                "Open Ports": summary.get("total_open_ports", 0),
                "Endpoints": summary.get("total_important_endpoints", 0),
            },
        },
    )
    write_json("outputs/scan_history.json", history[:50])


def clear_recon_outputs() -> dict[str, int]:
    targets = [Path("outputs/recon"), Path("outputs/zap"), Path("outputs/nuclei")]
    removed = {"files": 0, "directories": 0}
    for target in targets:
        if target.exists():
            shutil.rmtree(target)
            removed["directories"] += 1
    for path in [Path("reports/recon_report.html"), Path("reports/recon_report.pdf")]:
        if path.exists():
            path.unlink()
            removed["files"] += 1
    for path in Path("logs").glob("recon*.log") if Path("logs").exists() else []:
        if path.is_file():
            path.unlink()
            removed["files"] += 1
    return removed
