from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import requests

from agent.core.scope_validator import get_hostname, split_internal_external_urls
from agent.report.json_writer import read_json, write_json
from agent.utils.command_runner import command_exists, run_command
from agent.utils.tool_runner import record_tool_skipped, run_tool


def _safe_hostname(url: str) -> str:
    return get_hostname(url).replace(":", "_")


def _fallback_crawl(target: str) -> list[str]:
    response = requests.get(target, timeout=20)
    soup = BeautifulSoup(response.text, "html.parser")
    urls = {response.url}
    for tag in soup.find_all(["a", "link", "script", "img", "form"]):
        value = tag.get("href") or tag.get("src") or tag.get("action")
        if value:
            urls.add(urljoin(response.url, value))
    return sorted(urls)


def _merge_external(new_items: list[dict[str, object]], path: str = "outputs/external_dependencies.json") -> None:
    existing = read_json(path, default=[]) or []
    merged = {str(item.get("url")): item for item in existing if item.get("url")}
    for item in new_items:
        merged.setdefault(str(item.get("url")), item)
    write_json(path, list(merged.values()))


def run_katana(
    allowed_urls: list[str] | str,
    dynamic_allowed_hosts: list[str],
    max_urls_per_host: int = 200,
    command: str = "katana",
    output_path: str = "outputs/endpoints.json",
) -> list[str]:
    urls_to_crawl = [allowed_urls] if isinstance(allowed_urls, str) else allowed_urls
    raw_urls: list[str] = []
    raw_dir = Path("outputs/crawl_raw")
    raw_dir.mkdir(parents=True, exist_ok=True)

    for target in urls_to_crawl:
        host = _safe_hostname(target)
        raw_path = raw_dir / f"{host}_katana.txt"
        host_urls: list[str] = []
        if command_exists(command):
            completed = run_tool([command, "-u", target, "-silent"], timeout=300, tool_name="katana", output_path=str(raw_path), target=target)
            if completed.get("status") == "Done" and raw_path.exists():
                host_urls = [line.strip() for line in raw_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        else:
            record_tool_skipped("katana", "Tool not installed; using fallback crawler", target)
        if not host_urls:
            host_urls = _fallback_crawl(target)
            raw_path.write_text("\n".join(host_urls) + "\n", encoding="utf-8")
        raw_urls.extend(host_urls[:max_urls_per_host])

    internal, external = split_internal_external_urls(raw_urls, dynamic_allowed_hosts)
    deduped_internal = list(dict.fromkeys(internal))
    write_json(output_path, deduped_internal)
    _merge_external(external)
    return deduped_internal
