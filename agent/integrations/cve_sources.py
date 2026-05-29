from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests


def _cache_path(cache_dir: str, key: str) -> Path:
    safe = "".join(ch if ch.isalnum() else "_" for ch in key.lower())
    return Path(cache_dir) / f"{safe}.json"


def query_nvd(product: str, version: str | None, config: dict[str, object]) -> list[dict[str, Any]]:
    cve_cfg = config.get("cve", {}) if isinstance(config.get("cve"), dict) else {}
    cache_dir = str(cve_cfg.get("cache_dir", "data/cve_cache"))
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    key = f"nvd_{product}_{version or 'any'}"
    cache = _cache_path(cache_dir, key)
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    if not cve_cfg.get("nvd_enabled", True):
        return []
    params = {"keywordSearch": f"{product} {version or ''}".strip(), "resultsPerPage": int(cve_cfg.get("max_results_per_product", 20))}
    headers = {}
    if cve_cfg.get("nvd_api_key"):
        headers["apiKey"] = str(cve_cfg["nvd_api_key"])
    try:
        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers, timeout=int(cve_cfg.get("request_timeout_seconds", 15)))
        data = response.json().get("vulnerabilities", []) if response.status_code == 200 else []
    except Exception:
        data = []
    cache.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


def query_osv(product: str, version: str | None, config: dict[str, object]) -> list[dict[str, Any]]:
    cve_cfg = config.get("cve", {}) if isinstance(config.get("cve"), dict) else {}
    if not cve_cfg.get("osv_enabled", True) or not version:
        return []
    try:
        response = requests.post("https://api.osv.dev/v1/query", json={"version": version, "package": {"name": product}}, timeout=int(cve_cfg.get("request_timeout_seconds", 15)))
        return response.json().get("vulns", []) if response.status_code == 200 else []
    except Exception:
        return []
