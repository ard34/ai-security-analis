from __future__ import annotations

from urllib.parse import urlparse

from agent.report.json_writer import read_json, write_json


def analyze_api_top10(output_path: str = "outputs/api_top10_candidates.json") -> list[dict[str, object]]:
    endpoints = read_json("outputs/recon/important_endpoints.json", default=[]) or []
    external = read_json("outputs/external_dependencies.json", default=[]) or []
    candidates = []
    for item in endpoints:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", ""))
        lower = url.lower()
        category = item.get("category", "")
        def add(api_id: str, name: str, focus: str) -> None:
            candidates.append({"api_id": api_id, "api_name": name, "endpoint": url, "affected_host": urlparse(url).hostname or "", "reason": focus, "manual_validation_required": True, "status": "Potential"})
        if "/api/" in lower and any(key in lower for key in ["id=", "/id", "order", "invoice", "user"]):
            add("API1", "Broken Object Level Authorization", "Object ID endpoint perlu validasi BOLA.")
        if category in {"auth", "register"}:
            add("API2", "Broken Authentication", "Auth/session indicator perlu validasi.")
        if any(key in lower for key in ["upload", "export", "search"]):
            add("API4", "Unrestricted Resource Consumption", "Operasi berat perlu limit/rate review.")
        if "admin" in lower or category == "admin-like":
            add("API5", "Broken Function Level Authorization", "Endpoint admin/function perlu validasi role.")
        if any(key in lower for key in ["payment", "checkout", "coupon", "order"]):
            add("API6", "Unrestricted Access to Sensitive Business Flows", "Flow bisnis sensitif perlu validasi.")
        if any(key in lower for key in ["url=", "webhook", "fetch", "callback"]):
            add("API7", "Server Side Request Forgery", "Parameter URL/webhook perlu allowlist review.")
        if any(key in lower for key in ["/v1/", "/beta", "debug"]):
            add("API9", "Improper Inventory Management", "Versioning/debug endpoint perlu review inventory.")
    for dep in external if isinstance(external, list) else []:
        if isinstance(dep, dict):
            candidates.append({"api_id": "API10", "api_name": "Unsafe Consumption of APIs", "endpoint": dep.get("url", ""), "affected_host": dep.get("hostname", ""), "reason": "Dependensi/API eksternal terlihat.", "manual_validation_required": True, "status": "Potential"})
    write_json(output_path, candidates)
    return candidates
