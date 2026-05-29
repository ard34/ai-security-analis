from __future__ import annotations

import re
from urllib.parse import urljoin

import requests

from agent.report.json_writer import write_json
from agent.utils.command_runner import command_exists, run_command
from agent.utils.tool_runner import record_tool_skipped, run_tool


CHECKS = {
    "nginx": ["nginx"],
    "Apache": ["apache"],
    "IIS": ["microsoft-iis", "iis"],
    "PHP": ["php", ".php", "phpsessid", "x-powered-by: php"],
    "Laravel": ["laravel", "x-csrf-token"],
    "Node.js": ["node.js", "nodejs", "express"],
    "Express": ["express"],
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Next.js": ["_next/static", "next.js"],
    "React": ["react", "__react", "react-dom"],
    "Vue": ["vue", "__vue"],
    "Angular": ["ng-version", "angular"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
    "Cloudflare": ["cloudflare", "cf-cache-status", "cf-ray"],
    "Akamai": ["akamai", "akamai-ghost"],
    "Fastly": ["fastly", "x-served-by"],
    "Sucuri": ["sucuri"],
    "API/JSON": ["application/json", "/api/"],
}


def _extract_assets(base_url: str, html: str) -> dict[str, list[str]]:
    scripts = [urljoin(base_url, item) for item in re.findall(r"<script[^>]+src=[\"']([^\"']+)", html, re.I)]
    links = [urljoin(base_url, item) for item in re.findall(r"<link[^>]+href=[\"']([^\"']+)", html, re.I)]
    generators = re.findall(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", html, re.I)
    return {"script_src": scripts[:100], "link_href": links[:100], "meta_generator": generators[:20]}


def fingerprint_web_hosts(live_hosts: list[dict[str, object]], whatweb_command: str = "whatweb", output_path: str = "outputs/recon/technologies.json") -> list[dict[str, object]]:
    results = []
    for host in live_hosts:
        url = str(host.get("url", ""))
        if not url:
            continue
        try:
            response = requests.get(url, timeout=12, allow_redirects=True)
            html = response.text[:200000]
            header_text = " ".join(f"{k}: {v}" for k, v in response.headers.items()).lower()
            haystack = f"{html.lower()} {header_text} {response.headers.get('content-type', '').lower()}"
            detected = [{"technology": name, "evidence": ", ".join(marker for marker in markers if marker in haystack)} for name, markers in CHECKS.items() if any(marker in haystack for marker in markers)]
            assets = _extract_assets(response.url, html)
        except Exception as exc:
            results.append({"host": host.get("hostname", ""), "url": url, "status": "failed", "reason": str(exc), "detected": []})
            continue
        whatweb_output = ""
        if command_exists(whatweb_command):
            completed = run_tool([whatweb_command, response.url], timeout=60, tool_name="whatweb", target=response.url)
            whatweb_output = re.sub(r"\x1b\[[0-9;]*m", "", (str(completed.get("stdout", "")) or str(completed.get("stderr", ""))).strip())[:5000]
        else:
            record_tool_skipped("whatweb", "Tool not installed", response.url)
        results.append(
            {
                "host": host.get("hostname", ""),
                "url": response.url,
                "headers": {key: value for key, value in response.headers.items() if key.lower() in {"server", "x-powered-by", "via", "cf-cache-status", "x-cdn", "content-type"}},
                "detected": detected,
                "assets": assets,
                "whatweb": whatweb_output,
                "status": "collected",
            }
        )
    write_json(output_path, results)
    write_json("outputs/technology_fingerprint.json", {"hosts": results, "note": "Fingerprint evidence only. CVE correlation is potential until manually validated."})
    return results
