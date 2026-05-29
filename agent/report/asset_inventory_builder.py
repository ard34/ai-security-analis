from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse

from agent.report.json_writer import read_json, write_json


IMPORTANT_ENDPOINT_LABELS = {
    "auth",
    "register",
    "api",
    "admin-like",
    "profile",
    "account",
    "order",
    "invoice",
    "payment",
    "file-upload",
    "file-download",
    "search",
}


def _host_fingerprints() -> dict[str, dict[str, object]]:
    data = read_json("outputs/technology_fingerprint.json", default={}) or {}
    results = {}
    for item in data.get("hosts", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        host = urlparse(str(item.get("final_url") or item.get("target") or "")).hostname or ""
        if host:
            results[host.lower()] = item
    return results


def _tech_names(item: dict[str, object]) -> list[str]:
    detected = item.get("detected", [])
    names = [str(tech.get("technology")) for tech in detected if isinstance(tech, dict) and tech.get("technology")]
    headers = item.get("headers", {}) if isinstance(item.get("headers"), dict) else {}
    server = str(headers.get("server") or headers.get("Server") or "")
    if server:
        names.append(server)
    return sorted(dict.fromkeys(names))


def _category(technology: str) -> str:
    value = technology.lower()
    if any(item in value for item in ["cloudflare", "akamai", "fastly", "cloudfront", "waf", "cdn"]):
        return "waf_cdn"
    if any(item in value for item in ["nginx", "apache", "server"]):
        return "web_server"
    if any(item in value for item in ["react", "vue", "angular", "express", "laravel"]):
        return "framework"
    if any(item in value for item in ["jquery", "bootstrap"]):
        return "javascript_libraries"
    if any(item in value for item in ["php", "node"]):
        return "backend_language_indicators"
    if "wordpress" in value:
        return "cms"
    if "api" in value:
        return "api_indicators"
    return "other"


def build_asset_inventory(output_path: str = "outputs/asset_inventory.json") -> dict[str, object]:
    live_hosts = read_json("outputs/live_hosts.json", default=[]) or []
    endpoints = read_json("outputs/endpoints.json", default=[]) or []
    classifications = read_json("outputs/endpoint_classification.json", default=[]) or []
    auth_endpoints = read_json("outputs/auth_endpoints.json", default=[]) or []
    fingerprints = _host_fingerprints()

    assets = []
    technology_stack: dict[str, set[str]] = defaultdict(set)
    for category in ["web_server", "framework", "javascript_libraries", "backend_language_indicators", "cms", "waf_cdn", "api_indicators"]:
        technology_stack[category] = set()
    for host in live_hosts:
        if not isinstance(host, dict):
            continue
        hostname = str(host.get("hostname", "")).lower()
        fp = fingerprints.get(hostname, {})
        tech = _tech_names(fp) or [str(item) for item in host.get("tech", []) if item]
        for item in tech:
            technology_stack[_category(item)].add(item)
        waf = ", ".join(item for item in tech if any(marker in item.lower() for marker in ["cloudflare", "akamai", "fastly", "cloudfront", "waf", "cdn"]))
        server = str(host.get("webserver") or (fp.get("headers", {}) if isinstance(fp.get("headers"), dict) else {}).get("server", ""))
        assets.append(
            {
                "hostname": hostname,
                "url": host.get("url", ""),
                "status_code": host.get("status_code", ""),
                "title": host.get("title", ""),
                "server": server,
                "cdn_waf": waf,
                "technologies": tech,
                "framework": ", ".join(item for item in tech if item.lower() in {"react", "vue", "angular", "express", "laravel"}),
                "language_indication": ", ".join(item for item in tech if item.lower() in {"php", "node.js"}),
                "cms_indication": ", ".join(item for item in tech if "wordpress" in item.lower()),
                "notes": "Fingerprint evidence only; validate manually.",
            }
        )

    endpoint_class = {str(item.get("url")): str(item.get("classification", "unknown")) for item in classifications if isinstance(item, dict)}
    important = []
    keywords = ("admin", "profile", "account", "order", "invoice", "payment", "upload", "download", "search", "api", "login", "signin", "register")
    for url in endpoints:
        value = str(url)
        label = endpoint_class.get(value, "auth" if value in auth_endpoints else "unknown")
        if label in IMPORTANT_ENDPOINT_LABELS or any(keyword in value.lower() for keyword in keywords):
            important.append({"url": value, "hostname": urlparse(value).hostname or "", "classification": label})

    data = {
        "assets": assets,
        "technology_stack": {key: sorted(values) for key, values in technology_stack.items()},
        "important_endpoints": important,
    }
    write_json(output_path, data)
    return data
