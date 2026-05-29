from __future__ import annotations

from agent.report.json_writer import write_json


SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status", "__cf_bm"],
    "Akamai": ["akamai", "akamai-ghost", "x-akamai"],
    "Fastly": ["fastly", "x-served-by", "x-cache-hits"],
    "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
}


def detect_waf_cdn(header_results: list[dict[str, object]], technology_results: list[dict[str, object]], output_path: str = "outputs/recon/waf_cdn.json") -> list[dict[str, object]]:
    by_host: dict[str, str] = {}
    for item in header_results + technology_results:
        host = str(item.get("host") or item.get("hostname") or "")
        text = str(item).lower()
        matches = [name for name, markers in SIGNATURES.items() if any(marker in text for marker in markers)]
        if matches:
            by_host[host] = ", ".join(sorted(set(matches)))
    results = [{"host": host, "provider": provider, "method": "passive_headers_and_fingerprint", "bypass_attempted": False} for host, provider in sorted(by_host.items())]
    write_json(output_path, results)
    return results
