from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

from agent.core.target_normalizer import NormalizedTarget
from agent.recon.recon_progress import log_step
from agent.report.json_writer import read_json, write_json
from agent.utils.command_runner import command_exists, run_command
from agent.utils.tool_runner import record_tool_skipped, run_tool


def _title(text: str) -> str:
    lower = text.lower()
    if "<title" not in lower:
        return ""
    return text.split("<title", 1)[-1].split(">", 1)[-1].split("</title>", 1)[0].strip()[:120]


def _requests_probe(url: str, hostname: str, target_type: str) -> dict[str, object] | None:
    started = time.monotonic()
    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
    except requests.RequestException:
        return None
    elapsed = round(time.monotonic() - started, 3)
    return {
        "hostname": hostname,
        "url": response.url,
        "scheme": urlparse(response.url).scheme or urlparse(url).scheme,
        "status_code": response.status_code,
        "title": _title(response.text),
        "webserver": response.headers.get("Server", ""),
        "technologies": [],
        "content_type": response.headers.get("Content-Type", ""),
        "response_time": elapsed,
        "target_type": target_type,
        "source": "python_requests",
    }


def _host_from_item(item: dict[str, object]) -> str:
    value = str(item.get("url") or item.get("host") or item.get("input") or item.get("hostname") or "")
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value).lower().strip(".")


def _httpx_probe(input_path: str, output_path: str, command: str) -> list[dict[str, object]]:
    result = run_tool([command, "-l", input_path, "-silent", "-json", "-title", "-tech-detect", "-status-code", "-web-server"], timeout=300, tool_name="httpx", output_path=output_path)
    if result.get("status") != "Done" or not Path(output_path).exists():
        return []
    results = []
    for line in Path(output_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        host = _host_from_item(item)
        url = str(item.get("url", ""))
        results.append(
            {
                "hostname": host,
                "url": url,
                "scheme": urlparse(url).scheme,
                "status_code": item.get("status_code"),
                "title": item.get("title", ""),
                "webserver": item.get("webserver", ""),
                "technologies": item.get("tech", []) or [],
                "content_type": item.get("content_type", ""),
                "response_time": item.get("response_time", ""),
                "target_type": "web",
                "source": "httpx",
            }
        )
    return results


def _probe_candidates(subdomains: list[object], normalized: NormalizedTarget) -> list[str]:
    hosts = {normalized.registered_domain, normalized.hostname}
    for item in subdomains:
        if isinstance(item, dict) and item.get("hostname"):
            hosts.add(str(item["hostname"]).lower().strip("."))
    return sorted(host for host in hosts if host)


def _probe_urls(hosts: list[str]) -> list[str]:
    urls: list[str] = []
    for host in hosts:
        urls.extend([f"https://{host}", f"http://{host}"])
    return urls


def _dedupe_prefer_https(results: list[dict[str, object]]) -> list[dict[str, object]]:
    by_host: dict[str, dict[str, object]] = {}
    for item in results:
        host = str(item.get("hostname", "")).lower().strip(".")
        if not host:
            continue
        current = by_host.get(host)
        if current is None:
            by_host[host] = item
            continue
        current_scheme = str(current.get("scheme") or urlparse(str(current.get("url", ""))).scheme)
        item_scheme = str(item.get("scheme") or urlparse(str(item.get("url", ""))).scheme)
        if current_scheme != "https" and item_scheme == "https":
            by_host[host] = item
    return [by_host[host] for host in sorted(by_host)]


def discover_live_hosts(config: dict[str, object], normalized: NormalizedTarget, output_dir: str = "outputs/recon") -> list[dict[str, object]]:
    log_step("HTTP Probing", "running", "HTTP probing dimulai.")
    subdomains = read_json(f"{output_dir}/discovered_subdomains.json", default=[]) or []
    httpx = str((config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}).get("httpx", "httpx"))
    results: list[dict[str, object]] = []
    candidates = _probe_candidates(subdomains, normalized)

    if normalized.direct_scope:
        record_tool_skipped("httpx", "Direct target scope uses exact URL Python requests probe", normalized.normalized_url)
        probed = _requests_probe(normalized.normalized_url, normalized.hostname, normalized.target_kind)
        results = [probed] if probed else []
    elif command_exists(httpx):
        input_path = f"{output_dir}/http_probe_targets.txt"
        Path(input_path).write_text("\n".join(_probe_urls(candidates)) + ("\n" if candidates else ""), encoding="utf-8")
        results = _httpx_probe(input_path, f"{output_dir}/live_hosts_raw.jsonl", httpx)
    else:
        record_tool_skipped("httpx", "Tool not installed; using Python requests fallback", normalized.registered_domain)

    if not results:
        for hostname in candidates:
            for scheme in ("https", "http"):
                probed = _requests_probe(f"{scheme}://{hostname}", hostname, "web")
                if probed:
                    results.append(probed)
                    break
    results = _dedupe_prefer_https([item for item in results if item])

    write_json(f"{output_dir}/live_hosts.json", results)
    write_json(
        f"{output_dir}/http_probe_summary.json",
        {
            "total_candidates": len(candidates) if not normalized.direct_scope else 1,
            "probed": len(candidates) if not normalized.direct_scope else 1,
            "live_hosts": len(results),
            "dead_hosts": max((len(subdomains) if not normalized.direct_scope else 1) - len(results), 0),
            "tool": "python_requests" if normalized.direct_scope or not command_exists(httpx) else "httpx",
            "fallback_used": normalized.direct_scope or not command_exists(httpx),
        },
    )
    write_json("outputs/live_hosts.json", [{"hostname": item.get("hostname"), "url": item.get("url"), "scheme": item.get("scheme"), "status_code": item.get("status_code"), "title": item.get("title"), "webserver": item.get("webserver"), "technologies": item.get("technologies", []), "source": item.get("source")} for item in results])
    log_step("HTTP Probing", "done", "HTTP probing selesai.", {"live_hosts": len(results)})
    return results
