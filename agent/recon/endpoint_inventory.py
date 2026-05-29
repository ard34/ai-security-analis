from __future__ import annotations

from urllib.parse import urlparse

from agent.report.json_writer import write_json
from agent.traffic.endpoint_classifier import classify_endpoint


def build_important_endpoints(endpoints: list[str], output_path: str = "outputs/recon/important_endpoints.json") -> list[dict[str, object]]:
    important_labels = {"auth", "register", "api", "admin-like", "profile", "account", "order", "invoice", "payment", "file-upload", "file-download", "search"}
    keywords = ("login", "signin", "logout", "register", "reset", "api", "admin", "profile", "account", "upload", "download", "search", "order", "invoice", "payment", "form")
    results = []
    for url in endpoints:
        entry = {"url": url, "method": "GET", "query_params": dict(), "content_type": ""}
        label = classify_endpoint(entry)
        if label in important_labels or any(keyword in url.lower() for keyword in keywords):
            results.append({"url": url, "hostname": urlparse(url).hostname or "", "category": label if label != "unknown" else "important"})
    write_json(output_path, results)
    return results
