from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


RECON_DIR = Path("outputs/recon")
ZAP_DIR = Path("outputs/zap")
NUCLEI_DIR = Path("outputs/nuclei")


def _read_json(path: str | Path, default: Any) -> Any:
    file_path = Path(path)
    if not file_path.exists():
        return default
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("items", "results", "records", "hosts", "urls", "alerts", "screenshots"):
            if isinstance(value.get(key), list):
                return value[key]
    return []


def _count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        if "count" in value:
            try:
                return int(value["count"])
            except Exception:
                return 0
        return sum(len(v) for v in value.values() if isinstance(v, list))
    return 0


def _mtime(path: str | Path) -> str:
    file_path = Path(path)
    if not file_path.exists():
        return ""
    return datetime.fromtimestamp(file_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")


def _tool_runs() -> list[dict[str, Any]]:
    return _list(_read_json(RECON_DIR / "tool_run_log.json", []))


def _run_for(*names: str) -> dict[str, Any]:
    aliases = {name.lower() for name in names}
    for item in reversed(_tool_runs()):
        if isinstance(item, dict) and str(item.get("tool", "")).lower() in aliases:
            return item
    return {}


def _status_for(count: int, *names: str) -> str:
    run = _run_for(*names)
    status = str(run.get("status", ""))
    if status:
        return status
    return "Done" if count else "Pending"


def _last_run_for(path: str | Path, *names: str) -> str:
    run = _run_for(*names)
    return str(run.get("finished_at") or run.get("started_at") or _mtime(path))


def load_tool_counts() -> list[dict[str, Any]]:
    by_source = _read_json(RECON_DIR / "subdomains_by_source.json", {})
    if not isinstance(by_source, dict):
        by_source = {}
    mappings = [
        ("Subfinder Results", "subfinder", len(_list(by_source.get("subfinder"))), RECON_DIR / "subdomains_by_source.json", ("subfinder",)),
        ("Amass Results", "amass", len(_list(by_source.get("amass"))), RECON_DIR / "subdomains_by_source.json", ("amass", "amass passive")),
        ("Assetfinder Results", "assetfinder", len(_list(by_source.get("assetfinder"))), RECON_DIR / "subdomains_by_source.json", ("assetfinder",)),
        ("Certificate Transparency Results", "certificate_transparency", len(_list(by_source.get("certificate_transparency"))), RECON_DIR / "subdomains_by_source.json", ("certificate_transparency", "ct")),
        ("DNS Records", "dns_records", _count(_read_json(RECON_DIR / "dns_records.json", [])), RECON_DIR / "dns_records.json", ("dns records", "dns")),
        ("DNSx Validated Hosts", "dnsx", _count(_read_json(RECON_DIR / "dns_validated_hosts.json", [])), RECON_DIR / "dns_validated_hosts.json", ("dnsx",)),
        ("HTTPx Live Hosts", "httpx", _count(_read_json(RECON_DIR / "live_hosts.json", [])), RECON_DIR / "live_hosts.json", ("httpx",)),
        ("Nmap Open Ports", "nmap", _count(_read_json(RECON_DIR / "open_ports.json", [])), RECON_DIR / "open_ports.json", ("nmap",)),
        ("WhatWeb Technologies", "whatweb", _count(_read_json(RECON_DIR / "technologies.json", [])), RECON_DIR / "technologies.json", ("whatweb",)),
        ("WAF/CDN Indicators", "waf_cdn", _count(_read_json(RECON_DIR / "waf_cdn.json", [])), RECON_DIR / "waf_cdn.json", ("waf/cdn detection", "waf_cdn")),
        ("Katana Endpoints", "katana", len([item for item in _list(_read_json(RECON_DIR / "endpoints.json", [])) if not isinstance(item, dict) or item.get("source") in (None, "", "katana")]), RECON_DIR / "endpoints.json", ("katana", "katana crawler")),
        ("OWASP ZAP URLs", "zap_urls", _count(_read_json(ZAP_DIR / "zap_urls.json", [])), ZAP_DIR / "zap_urls.json", ("owasp zap traditional spider", "owasp zap ajax spider", "zap_traditional_spider", "zap_ajax_spider")),
        ("OWASP ZAP Alerts", "zap_alerts", _count(_read_json(ZAP_DIR / "zap_passive_alerts.json", [])), ZAP_DIR / "zap_passive_alerts.json", ("owasp zap passive scan", "zap_passive_scan")),
        ("Nuclei Findings", "nuclei", _count(_read_json(NUCLEI_DIR / "nuclei_results.json", [])), NUCLEI_DIR / "nuclei_results.json", ("nuclei", "nuclei safe templates")),
        ("Screenshots / Evidence", "screenshots", _count(_read_json(RECON_DIR / "screenshot_index.json", [])), RECON_DIR / "screenshot_index.json", ("screenshot evidence",)),
    ]
    return [
        {"tool": label, "key": key, "count": count, "status": _status_for(count, *aliases), "last_run": _last_run_for(path, *aliases)}
        for label, key, count, path, aliases in mappings
    ]


def load_recon_summary() -> dict[str, Any]:
    summary = _read_json(RECON_DIR / "recon_summary.json", {})
    return summary if isinstance(summary, dict) else {}


def load_last_scan_status() -> dict[str, Any]:
    summary = load_recon_summary()
    history = _read_json("outputs/scan_history.json", [])
    if isinstance(history, list) and history and isinstance(history[0], dict):
        return history[0]
    target = summary.get("target", {}) if isinstance(summary.get("target"), dict) else {}
    status = summary.get("run_status") or summary.get("status_label") or ("Completed" if summary else "Ready")
    return {
        "target": target.get("registered_domain") or target.get("hostname") or target.get("normalized_url") or "",
        "mode": summary.get("recon_mode", ""),
        "selected_tools": summary.get("selected_tools", []),
        "started_at": summary.get("started_at", ""),
        "finished_at": summary.get("finished_at", _mtime(RECON_DIR / "recon_summary.json")),
        "duration_seconds": summary.get("duration_seconds", ""),
        "status": status,
    }


def load_attack_surface_counts() -> dict[str, int]:
    subdomains = _read_json(RECON_DIR / "subdomains_all_sources.json", [])
    live_hosts = _read_json(RECON_DIR / "live_hosts.json", [])
    open_ports = _read_json(RECON_DIR / "open_ports.json", [])
    services = _read_json(RECON_DIR / "services.json", [])
    technologies = _read_json(RECON_DIR / "technologies.json", [])
    endpoints = _read_json(RECON_DIR / "endpoints.json", [])
    waf = _read_json(RECON_DIR / "waf_cdn.json", [])
    external = _read_json("outputs/external_dependencies.json", [])
    return {
        "Total Hostnames": _count(subdomains),
        "Live Hosts": _count(live_hosts),
        "Open Ports": _count(open_ports),
        "Services": _count(services),
        "Technologies": _count(technologies),
        "Endpoints": _count(endpoints),
        "WAF/CDN Detected": _count(waf),
        "External Dependencies": _count(external),
    }


def load_progress_events() -> list[dict[str, Any]]:
    latest = _read_json(RECON_DIR / "recon_progress_latest.json", [])
    rows = _list(latest)
    return [row for row in rows if isinstance(row, dict)] or _read_jsonl(RECON_DIR / "recon_progress.jsonl")


def read_output(path: str | Path, default: Any = None) -> Any:
    return _read_json(path, default)
