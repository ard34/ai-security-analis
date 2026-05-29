from __future__ import annotations

import json
from pathlib import Path

import requests

from agent.report.json_writer import read_json, write_json
from agent.utils.command_runner import command_exists, run_command


def _result_from_response(hostname: str, response: requests.Response) -> dict[str, object]:
    title = ""
    if "<title" in response.text.lower():
        title = response.text.split("<title", 1)[-1].split(">", 1)[-1].split("</title>", 1)[0].strip()[:120]
    return {
        "hostname": hostname,
        "url": response.url,
        "status_code": response.status_code,
        "title": title,
        "webserver": response.headers.get("Server", ""),
        "tech": [],
        "source": "python_requests",
    }


def _requests_probe_url(url: str, hostname: str) -> dict[str, object] | None:
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return _result_from_response(hostname, response)
    except requests.RequestException:
        return None


def _requests_probe(hostname: str) -> dict[str, object] | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            return _result_from_response(hostname, response)
        except requests.RequestException:
            continue
    return None


def probe_http(config: dict[str, object], discovered_path: str = "outputs/discovered_subdomains.json") -> list[dict[str, object]]:
    discovered = read_json(discovered_path, default=[]) or []
    hostnames = [str(item.get("hostname")) for item in discovered if item.get("hostname")]
    exact_targets = [(str(item.get("url")), str(item.get("hostname"))) for item in discovered if isinstance(item, dict) and item.get("url") and item.get("hostname")]
    tools_config = config.get("tools", {}) if isinstance(config.get("tools"), dict) else {}
    httpx_command = str(tools_config.get("httpx", "httpx"))
    results: list[dict[str, object]] = []

    if command_exists(httpx_command) and hostnames:
        list_path = Path("outputs/subdomains_for_probe.txt")
        inputs = [url for url, _host in exact_targets] or hostnames
        list_path.write_text("\n".join(inputs) + "\n", encoding="utf-8")
        raw_path = Path("outputs/live_hosts_raw.jsonl")
        completed = run_command([httpx_command, "-l", str(list_path), "-silent", "-json", "-o", str(raw_path)], timeout=300)
        if completed.returncode == 0 and raw_path.exists():
            for line in raw_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                host = item.get("host") or item.get("input") or item.get("hostname")
                results.append(
                    {
                        "hostname": str(host).lower().strip("."),
                        "url": item.get("url", ""),
                        "status_code": item.get("status_code"),
                        "title": item.get("title", ""),
                        "webserver": item.get("webserver", ""),
                        "tech": item.get("tech", []) or [],
                        "source": "httpx",
                    }
                )

    if not results:
        for exact_url, hostname in exact_targets:
            probed = _requests_probe_url(exact_url, hostname)
            if probed:
                results.append(probed)
        for hostname in hostnames:
            if any(item.get("hostname") == hostname for item in results):
                continue
            probed = _requests_probe(hostname)
            if probed:
                results.append(probed)

    write_json("outputs/live_hosts.json", results)
    return results
