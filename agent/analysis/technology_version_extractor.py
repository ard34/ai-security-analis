from __future__ import annotations

import re
from urllib.parse import urlparse

from agent.report.json_writer import read_json, write_json


VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9_. -]{1,40})[/ ]([0-9]+(?:\.[0-9A-Za-z-]+){0,4})")


def _add(products: list[dict[str, object]], product: str, version: str | None, host: str, url: str, evidence: str, source: str, confidence: str = "Medium") -> None:
    products.append({"product": product.strip(), "vendor": "", "version": version, "version_confidence": confidence if version else "Low", "host": host, "url": url, "evidence": evidence[:500], "source": source})


def extract_detected_products(output_path: str = "outputs/detected_products.json") -> list[dict[str, object]]:
    products: list[dict[str, object]] = []
    for item in read_json("outputs/recon/services.json", default=[]) or []:
        if isinstance(item, dict) and item.get("service"):
            _add(products, str(item.get("product") or item.get("service")), str(item.get("version") or "") or None, str(item.get("host", "")), "", str(item), "nmap", "High" if item.get("version") else "Low")
    for item in read_json("outputs/recon/live_hosts.json", default=[]) or []:
        if isinstance(item, dict):
            server = str(item.get("webserver") or "")
            for match in VERSION_RE.finditer(server):
                _add(products, match.group(1), match.group(2), str(item.get("hostname", "")), str(item.get("url", "")), server, "httpx/header", "High")
            for tech in item.get("technologies", []) if isinstance(item.get("technologies"), list) else []:
                _add(products, str(tech), None, str(item.get("hostname", "")), str(item.get("url", "")), str(tech), "httpx", "Low")
    for item in read_json("outputs/recon/technologies.json", default=[]) or []:
        if isinstance(item, dict):
            host = str(item.get("host", ""))
            url = str(item.get("url", ""))
            for detected in item.get("detected", []) if isinstance(item.get("detected"), list) else []:
                if isinstance(detected, dict):
                    _add(products, str(detected.get("technology")), None, host, url, str(detected), "html fingerprint", "Low")
            text = f"{item.get('whatweb', '')} {item.get('headers', '')}"
            for match in VERSION_RE.finditer(text):
                _add(products, match.group(1), match.group(2), host, url, text, "whatweb", "Medium")
    dedup = {}
    for item in products:
        key = (item["product"], item.get("version"), item.get("host"), item.get("url"))
        dedup[key] = item
    result = list(dedup.values())
    write_json(output_path, result)
    return result
