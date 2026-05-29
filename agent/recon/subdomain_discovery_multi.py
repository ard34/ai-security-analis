from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from agent.core.scope_validator import get_registered_domain, is_same_registered_domain
from agent.core.target_normalizer import NormalizedTarget
from agent.recon.certificate_transparency import collect_ct_subdomains
from agent.recon.recon_progress import log_step, log_tool_skipped
from agent.report.json_writer import read_json, write_json
from agent.utils.command_runner import command_exists
from agent.utils.tool_runner import record_tool_skipped, run_tool

SOURCES = ["target_input", "subfinder", "amass", "assetfinder", "certificate_transparency", "dns_records", "html_links"]


def _write_raw(source: str, hosts: list[str]) -> None:
    path = Path(f"outputs/recon/raw/{source}.txt")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(set(hosts))) + ("\n" if hosts else ""), encoding="utf-8")


def _normalize(hostname: str) -> str:
    return hostname.lower().strip().strip("*.").strip(".")


def _parse_lines(text: str) -> list[str]:
    return [_normalize(line) for line in text.splitlines() if _normalize(line)]


def _run_subfinder(root: str) -> list[str]:
    if not command_exists("subfinder"):
        record_tool_skipped("subfinder", "Tool not installed", root)
        return []
    result = run_tool(["subfinder", "-d", root, "-all", "-recursive", "-silent"], 300, "subfinder", target=root)
    hosts = _parse_lines(str(result.get("stdout", "")))
    if result.get("status") != "Done" or not hosts:
        fallback = run_tool(["subfinder", "-d", root, "-silent"], 300, "subfinder", target=root)
        hosts = _parse_lines(str(fallback.get("stdout", "")))
    _write_raw("subfinder", hosts)
    return hosts


def _run_amass(root: str) -> list[str]:
    if not command_exists("amass"):
        record_tool_skipped("amass", "Tool not installed", root)
        return []
    result = run_tool(["amass", "enum", "-passive", "-d", root], 600, "amass", target=root)
    hosts = _parse_lines(str(result.get("stdout", "")))
    _write_raw("amass_passive", hosts)
    return hosts


def _run_assetfinder(root: str) -> list[str]:
    if not command_exists("assetfinder"):
        record_tool_skipped("assetfinder", "Tool not installed", root)
        return []
    result = run_tool(["assetfinder", "--subs-only", root], 300, "assetfinder", target=root)
    hosts = _parse_lines(str(result.get("stdout", "")))
    _write_raw("assetfinder", hosts)
    return hosts


def _dns_hostnames(root: str) -> list[str]:
    records = read_json("outputs/recon/dns_records.json", default=[]) or []
    hosts = []
    for item in records:
        value = str(item.get("value", "")) if isinstance(item, dict) else ""
        for candidate in re.findall(r"([a-zA-Z0-9.-]+\." + re.escape(root) + r")\.?", value):
            hosts.append(_normalize(candidate))
    _write_raw("dns_hostnames", hosts)
    return hosts


def _html_hostnames(url: str, root: str) -> list[str]:
    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
    except requests.RequestException:
        _write_raw("html_hostnames", [])
        return []
    hosts = []
    for value in re.findall(r"(?:href|src)=[\"']([^\"']+)", response.text, re.I):
        host = urlparse(urljoin(response.url, value)).hostname
        if host and is_same_registered_domain(host, root):
            hosts.append(_normalize(host))
    _write_raw("html_hostnames", hosts)
    return hosts


def _confidence(sources: list[str]) -> str:
    if len(sources) >= 2:
        return "High"
    if sources and sources[0] in {"target_input", "subfinder", "amass", "assetfinder", "certificate_transparency"}:
        return "Medium"
    return "Low"


def discover_subdomains_multi(config: dict[str, object], normalized: NormalizedTarget, output_dir: str = "outputs/recon") -> list[dict[str, object]]:
    log_step("Penemuan Subdomain", "running", "Penemuan subdomain pasif dimulai.")
    root = normalized.registered_domain
    by_source: dict[str, list[str]] = {source: [] for source in SOURCES}
    by_source["target_input"] = [root]
    if normalized.hostname != root:
        by_source["target_input"].append(normalized.hostname)

    if normalized.direct_scope or not normalized.subfinder_allowed:
        for source in ["subfinder", "amass", "assetfinder", "certificate_transparency", "dns_records", "html_links"]:
            record_tool_skipped(source, "Target is localhost/IP or subdomain recon disabled by assessment profile", root)
    else:
        by_source["subfinder"] = _run_subfinder(root)
        by_source["amass"] = _run_amass(root)
        by_source["assetfinder"] = _run_assetfinder(root)
        ct = collect_ct_subdomains(root, f"{output_dir}/ct_subdomains.json")
        by_source["certificate_transparency"] = [str(item.get("hostname")) for item in ct if isinstance(item, dict)]
        _write_raw("ct_subdomains", by_source["certificate_transparency"])
        by_source["dns_records"] = _dns_hostnames(root)
        by_source["html_links"] = _html_hostnames(normalized.normalized_url, root)

    accepted: dict[str, set[str]] = {}
    rejected = []
    for source, hosts in by_source.items():
        by_source[source] = sorted(set(_normalize(host) for host in hosts if host))
        for host in by_source[source]:
            same = is_same_registered_domain(host, root)
            if same and (host == root or host.endswith("." + root) or host == normalized.hostname):
                accepted.setdefault(host, set()).add(source)
            else:
                rejected.append({"hostname": host, "source": source, "root_domain": root, "accepted": False, "reject_reason": "outside_registered_domain"})

    items = []
    for hostname, sources in sorted(accepted.items()):
        source_list = sorted(sources)
        items.append(
            {
                "hostname": hostname,
                "sources": source_list,
                "source_count": len(source_list),
                "root_domain": root,
                "same_registered_domain": True,
                "accepted": True,
                "reject_reason": "",
                "confidence": _confidence(source_list),
                "source": ", ".join(source_list),
            }
        )

    write_json(f"{output_dir}/subdomains_by_source.json", by_source)
    write_json(f"{output_dir}/subdomains_all_sources.json", items + rejected)
    write_json(f"{output_dir}/rejected_subdomain_candidates.json", rejected)
    write_json(f"{output_dir}/discovered_subdomains.json", items)
    Path(f"{output_dir}/subdomains.txt").write_text("\n".join(item["hostname"] for item in items) + ("\n" if items else ""), encoding="utf-8")
    log_step("Penemuan Subdomain", "done", "Penemuan subdomain selesai.", {"accepted": len(items), "rejected": len(rejected), "sources": {k: len(v) for k, v in by_source.items()}})
    return items
