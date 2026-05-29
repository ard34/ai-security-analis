from __future__ import annotations

import json
from pathlib import Path

from agent.core.scope_validator import enforce_url_scope, get_hostname, load_dynamic_allowed_hosts
from agent.report.json_writer import read_json, write_json
from agent.utils.command_runner import command_exists, run_command


def run_nuclei(allowed_urls: list[str] | str | None = None, command: str = "nuclei") -> list[dict[str, object]]:
    if not command_exists(command):
        raise FileNotFoundError("nuclei command not found")

    scope = read_json("outputs/dynamic_allowed_hosts.json", default={}) or {}
    dynamic_allowed_hosts = load_dynamic_allowed_hosts()
    if not dynamic_allowed_hosts:
        raise ValueError("Dynamic allowed hosts not found. Build dynamic scope before running nuclei.")
    urls = allowed_urls
    if urls is None:
        urls = scope.get("allowed_urls", [])
    urls_to_scan = [urls] if isinstance(urls, str) else list(urls)

    output_dir = Path("outputs/nuclei")
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    for url in urls_to_scan:
        enforce_url_scope(url, dynamic_allowed_hosts)
        hostname = get_hostname(url)
        output_jsonl = output_dir / f"{hostname}.jsonl"
        cmd = [
            command,
            "-u",
            url,
            "-severity",
            "info,low,medium",
            "-exclude-tags",
            "dos,bruteforce,intrusive,fuzz",
            "-rl",
            "5",
            "-jsonl",
            "-o",
            str(output_jsonl),
        ]
        completed = run_command(cmd, timeout=600)
        if completed.returncode != 0:
            raise RuntimeError(f"nuclei failed for {url}: {completed.stderr.strip()}")
        if output_jsonl.exists():
            for line in output_jsonl.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    item = json.loads(line)
                    item["scanned_url"] = url
                    item["hostname"] = hostname
                    results.append(item)

    write_json("outputs/nuclei_results.json", results)
    return results
