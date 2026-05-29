from __future__ import annotations

import re
from typing import Any

import requests

from agent.report.json_writer import write_json
from agent.utils.command_runner import command_exists, run_command


def _detect_from_html(html: str, headers: dict[str, str]) -> list[dict[str, str]]:
    haystack = html.lower()
    checks = {
        "Laravel": ["laravel", "x-csrf-token"],
        "PHP": [".php", "phpsessid"],
        "WordPress": ["wp-content", "wp-includes"],
        "Node.js": ["node.js", "nodejs"],
        "Express": ["express"],
        "React": ["react", "__react"],
        "Vue": ["vue", "__vue"],
        "Angular": ["ng-version", "angular"],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "Nginx": ["nginx"],
        "Apache": ["apache"],
        "Cloudflare": ["cloudflare", "cf-cache-status"],
        "CDN/WAF indication": ["cdn", "waf", "akamai", "fastly", "cloudfront", "cloudflare"],
    }
    header_text = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    findings = []
    for name, needles in checks.items():
        evidence = [needle for needle in needles if needle in haystack or needle in header_text]
        if evidence:
            findings.append({"technology": name, "evidence": ", ".join(evidence)})
    return findings


def fingerprint(target: str, whatweb_command: str = "whatweb", output_path: str = "outputs/technology_fingerprint.json") -> dict[str, Any]:
    response = requests.get(target, timeout=20)
    headers_of_interest = {
        key: value
        for key, value in response.headers.items()
        if key.lower() in {"server", "x-powered-by", "via", "cf-cache-status", "x-cdn"}
    }
    detected = _detect_from_html(response.text[:200000], dict(response.headers))

    whatweb_output = ""
    if command_exists(whatweb_command):
        completed = run_command([whatweb_command, target], timeout=60)
        whatweb_output = re.sub(r"\x1b\[[0-9;]*m", "", (completed.stdout or completed.stderr).strip())

    result = {
        "target": target,
        "final_url": response.url,
        "headers": headers_of_interest,
        "detected": detected,
        "whatweb": whatweb_output,
        "note": "Fingerprint evidence only. CVE correlation is potential until manually validated.",
    }
    write_json(output_path, result)
    return result
