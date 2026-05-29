from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from agent.integrations.zap_controller import zap_client
from agent.report.json_writer import read_json, write_json


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower().strip(".")


def _in_scope(url: str, allowed_hosts: list[str] | None) -> bool:
    if not allowed_hosts:
        return True
    host = _host(url)
    allowed = {item.lower().strip(".") for item in allowed_hosts if item}
    return host in allowed or any(host.endswith("." + item) for item in allowed)


def _dedupe_urls(urls: list[str], allowed_hosts: list[str] | None = None) -> list[str]:
    seen = set()
    results = []
    for url in urls:
        text = str(url or "").strip()
        if not text or text in seen or not _in_scope(text, allowed_hosts):
            continue
        seen.add(text)
        results.append(text)
    return sorted(results)


def _reachable(url: str) -> bool:
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        if response.status_code < 500:
            return True
    except requests.RequestException:
        pass
    try:
        response = requests.get(url, timeout=8, allow_redirects=True)
        return response.status_code < 500
    except requests.RequestException:
        return False


def normalize_target_urls(target_domain: str, live_hosts: list[dict[str, Any]] | None = None) -> list[str]:
    urls = []
    from_live_hosts = False
    for item in live_hosts or []:
        if isinstance(item, dict) and item.get("url"):
            urls.append(str(item["url"]))
            from_live_hosts = True
    if not urls:
        domain = str(target_domain or "").replace("https://", "").replace("http://", "").split("/", 1)[0].strip()
        if domain:
            urls.extend([f"https://{domain}", f"http://{domain}"])
    reachable = [url for url in _dedupe_urls(urls) if _reachable(url)]
    return reachable or (_dedupe_urls(urls) if from_live_hosts else [])


def _timeout(config: dict[str, Any], key: str = "spider_timeout_seconds", default: int = 180) -> int:
    zap_cfg = config.get("zap", {}) if isinstance(config.get("zap"), dict) else {}
    return int(zap_cfg.get(key, default) or default)


def _core_urls(config: dict[str, Any], allowed_hosts: list[str] | None = None) -> list[str]:
    try:
        urls = zap_client(config).core.urls()
    except Exception:
        urls = []
    return _dedupe_urls([str(url) for url in urls], allowed_hosts)


def build_endpoint_inventory_from_zap_urls(urls: list[str]) -> list[dict[str, Any]]:
    rows = []
    for url in _dedupe_urls(urls):
        parsed = urlparse(url)
        rows.append({"url": url, "host": parsed.hostname or "", "scheme": parsed.scheme, "path": parsed.path or "/", "source": "owasp_zap"})
    write_json("outputs/zap/zap_endpoint_inventory.json", rows)
    return rows


def run_traditional_spider(config: dict[str, Any], target_urls: list[str], allowed_hosts: list[str] | None = None) -> dict[str, Any]:
    Path("outputs/zap").mkdir(parents=True, exist_ok=True)
    zap = zap_client(config)
    timeout = _timeout(config)
    scans = []
    for url in target_urls:
        scan_id = str(zap.spider.scan(url))
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if str(zap.spider.status(scan_id)) == "100":
                break
            time.sleep(2)
        scans.append({"url": url, "scan_id": scan_id, "status": str(zap.spider.status(scan_id))})
    urls = _core_urls(config, allowed_hosts)
    write_json("outputs/zap/zap_urls.json", [{"url": url, "source": "traditional_spider"} for url in urls])
    inventory = build_endpoint_inventory_from_zap_urls(urls)
    summary = {"traditional_spider": {"status": "Done", "target_urls": target_urls, "urls_count": len(urls), "scans": scans}}
    existing = read_json("outputs/zap/zap_spider_summary.json", default={}) or {}
    if isinstance(existing, dict):
        existing.update(summary)
        summary = existing
    write_json("outputs/zap/zap_spider_summary.json", summary)
    return {"status": "Done", "urls": urls, "urls_count": len(urls), "inventory_count": len(inventory), "summary": summary}


def run_ajax_spider(config: dict[str, Any], target_urls: list[str], allowed_hosts: list[str] | None = None) -> dict[str, Any]:
    Path("outputs/zap").mkdir(parents=True, exist_ok=True)
    zap = zap_client(config)
    timeout = _timeout(config, "ajax_timeout_seconds", 180)
    scans = []
    for url in target_urls:
        zap.ajaxSpider.scan(url)
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if str(zap.ajaxSpider.status).lower() == "stopped":
                break
            time.sleep(2)
        scans.append({"url": url, "status": str(zap.ajaxSpider.status)})
    existing_urls = [str(item.get("url")) for item in read_json("outputs/zap/zap_urls.json", default=[]) or [] if isinstance(item, dict)]
    urls = _dedupe_urls(existing_urls + _core_urls(config, allowed_hosts), allowed_hosts)
    write_json("outputs/zap/zap_urls.json", [{"url": url, "source": "zap_spider"} for url in urls])
    inventory = build_endpoint_inventory_from_zap_urls(urls)
    summary = read_json("outputs/zap/zap_spider_summary.json", default={}) or {}
    if not isinstance(summary, dict):
        summary = {}
    summary["ajax_spider"] = {"status": "Done", "target_urls": target_urls, "urls_count": len(urls), "scans": scans}
    write_json("outputs/zap/zap_spider_summary.json", summary)
    return {"status": "Done", "urls": urls, "urls_count": len(urls), "inventory_count": len(inventory), "summary": summary}


def collect_zap_messages(config: dict[str, Any], allowed_hosts: list[str] | None = None) -> list[dict[str, Any]]:
    try:
        messages = zap_client(config).core.messages()
    except Exception:
        messages = []
    rows = []
    for item in messages if isinstance(messages, list) else []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or item.get("requestHeader", ""))
        if url and not _in_scope(url, allowed_hosts):
            continue
        rows.append(item)
        if len(rows) >= 5000:
            break
    write_json("outputs/zap/zap_messages.json", rows)
    return rows


def collect_zap_alerts(config: dict[str, Any], target_url: str | None = None, allowed_hosts: list[str] | None = None) -> list[dict[str, Any]]:
    try:
        alerts = zap_client(config).core.alerts(baseurl=target_url) if target_url else zap_client(config).core.alerts()
    except Exception:
        alerts = []
    rows = []
    for item in alerts if isinstance(alerts, list) else []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        if url and not _in_scope(url, allowed_hosts):
            continue
        item.setdefault("status", "Potential")
        rows.append(item)
    write_json("outputs/zap/zap_alerts_raw.json", rows)
    write_json("outputs/zap/zap_passive_alerts.json", rows)
    return rows


def wait_for_passive_scan(config: dict[str, Any], timeout_seconds: int = 60) -> None:
    started = time.monotonic()
    try:
        zap = zap_client(config)
        while time.monotonic() - started < timeout_seconds:
            remaining = int(zap.pscan.records_to_scan)
            if remaining <= 0:
                return
            time.sleep(2)
    except Exception:
        return
