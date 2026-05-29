from __future__ import annotations

import os
import time
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

from agent.core.scope_validator import get_hostname, is_allowed_url, load_dynamic_allowed_hosts
from agent.report.json_writer import read_json, write_json

SAFE_KEYWORDS = {
    "dashboard",
    "profile",
    "settings",
    "account",
    "edit",
    "post",
    "create",
    "search",
    "order",
    "invoice",
    "upload",
    "download",
    "api",
}
RISKY_KEYWORDS = {
    "delete",
    "remove",
    "destroy",
    "payment",
    "transfer",
    "purchase",
    "checkout",
    "confirm",
    "admin",
    "role",
    "permission",
    "password",
    "reset",
}
DESTRUCTIVE_KEYWORDS = {
    "delete",
    "remove",
    "destroy",
    "cancel payment",
    "submit payment",
    "transfer",
    "purchase",
    "checkout final",
    "confirm delete",
}


def _norm_url(url: str) -> str:
    clean, _fragment = urldefrag(url)
    return clean.rstrip("/")


def is_risky_action(url_or_text: str) -> bool:
    value = url_or_text.lower().replace("-", " ").replace("_", " ")
    return any(keyword in value for keyword in RISKY_KEYWORDS)


def is_destructive_action(url_or_text: str) -> bool:
    value = url_or_text.lower().replace("-", " ").replace("_", " ")
    return any(keyword in value for keyword in DESTRUCTIVE_KEYWORDS)


def is_sensitive_admin_like(url_or_text: str) -> bool:
    value = url_or_text.lower()
    return any(keyword in value for keyword in {"admin", "role", "permission"})


def _is_safe_navigation(url: str, text: str = "") -> bool:
    haystack = f"{url} {text}".lower()
    if is_destructive_action(haystack):
        return False
    return any(keyword in haystack for keyword in SAFE_KEYWORDS) or not is_risky_action(haystack)


def _merge_external(new_items: list[dict[str, object]], path: str = "outputs/external_dependencies.json") -> None:
    existing = read_json(path, default=[]) or []
    merged = {str(item.get("url")): item for item in existing if isinstance(item, dict) and item.get("url")}
    for item in new_items:
        merged.setdefault(str(item.get("url")), item)
    write_json(path, list(merged.values()))


def _discover_links(page: object, base_url: str, allowed_hosts: list[str]) -> tuple[list[dict[str, str]], list[dict[str, object]]]:
    anchors = page.locator("a[href]")
    links: list[dict[str, str]] = []
    external: list[dict[str, object]] = []
    for index in range(anchors.count()):
        anchor = anchors.nth(index)
        href = anchor.get_attribute("href") or ""
        if not href or href.startswith(("javascript:", "mailto:", "tel:")):
            continue
        absolute = _norm_url(urljoin(base_url, href))
        try:
            hostname = get_hostname(absolute)
        except ValueError:
            continue
        text = (anchor.inner_text(timeout=1000) or "").strip()[:200]
        if is_allowed_url(absolute, allowed_hosts):
            links.append({"url": absolute, "text": text})
        else:
            external.append({"url": absolute, "hostname": hostname, "reason": "outside_dynamic_scope_from_authenticated_crawl", "scanned": False, "analyzed": False})
    return links, external


def _record_forms(page: object, page_url: str) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    forms = []
    skipped = []
    form_locators = page.locator("form")
    for index in range(form_locators.count()):
        form = form_locators.nth(index)
        action = form.get_attribute("action") or page_url
        method = (form.get_attribute("method") or "GET").upper()
        action_url = _norm_url(urljoin(page_url, action))
        inputs = []
        fields = form.locator("input, textarea, select")
        for field_index in range(fields.count()):
            field = fields.nth(field_index)
            inputs.append(
                {
                    "name": field.get_attribute("name") or "",
                    "type": field.get_attribute("type") or field.evaluate("el => el.tagName.toLowerCase()"),
                }
            )
        metadata = {
            "page_url": page_url,
            "action": action_url,
            "method": method,
            "fields": inputs,
            "risky": is_risky_action(action_url),
            "submitted": False,
        }
        forms.append(metadata)
        if metadata["risky"]:
            skipped.append({"url": action_url, "reason": "risky_form_action", "manual_validation_required": True})
    return forms, skipped


def _try_safe_search(page: object) -> None:
    search_fields = page.locator("input[type='search'], input[name*='search' i], input[name='q' i]")
    if search_fields.count() == 0:
        return
    field = search_fields.first
    form = field.locator("xpath=ancestor::form[1]")
    action = form.get_attribute("action") if form.count() else ""
    if action and is_destructive_action(action):
        return
    try:
        field.fill("test", timeout=2000)
        field.press("Enter", timeout=2000)
        page.wait_for_load_state("domcontentloaded", timeout=5000)
    except Exception:
        return


def run_authenticated_crawl(target_url: str, config: dict[str, object], har_path: str = "tmp/authenticated_session.har") -> dict[str, object]:
    from playwright.sync_api import sync_playwright

    allowed_hosts = load_dynamic_allowed_hosts()
    if not allowed_hosts:
        raise ValueError("Dynamic allowed hosts not found. Build dynamic scope before authenticated crawl.")
    if not is_allowed_url(target_url, allowed_hosts):
        raise ValueError(f"Target URL is outside dynamic allowed hosts: {target_url}")

    proxy = config.get("proxy", {}) if isinstance(config.get("proxy"), dict) else {}
    browser = config.get("browser", {}) if isinstance(config.get("browser"), dict) else {}
    scan = config.get("scan", {}) if isinstance(config.get("scan"), dict) else {}
    host = str(proxy.get("host", "127.0.0.1"))
    port = int(proxy.get("port", 8080))
    user_data_dir = os.path.expanduser(str(browser.get("user_data_dir") or "~/.config/ai-security-analyst/playwright-profile"))
    max_urls_per_host = int(scan.get("max_urls_per_host", 200))
    rate_limit = float(scan.get("rate_limit_seconds", 1))

    Path(har_path).parent.mkdir(parents=True, exist_ok=True)
    crawled: list[str] = []
    queued: list[dict[str, str]] = [{"url": _norm_url(target_url), "text": ""}]
    seen = set()
    forms: list[dict[str, object]] = []
    risky_skipped: list[dict[str, object]] = []
    external: list[dict[str, object]] = []

    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            user_data_dir,
            headless=False,
            proxy={"server": f"http://{host}:{port}"},
            ignore_https_errors=True,
            record_har_path=har_path,
            record_har_content="embed",
        )
        page = context.pages[0] if context.pages else context.new_page()
        while queued and len(crawled) < max_urls_per_host:
            item = queued.pop(0)
            url = _norm_url(item["url"])
            if url in seen:
                continue
            seen.add(url)
            if not is_allowed_url(url, allowed_hosts):
                external.append({"url": url, "hostname": get_hostname(url), "reason": "outside_dynamic_scope_from_authenticated_crawl", "scanned": False, "analyzed": False})
                continue
            if not _is_safe_navigation(url, item.get("text", "")):
                risky_skipped.append({"url": url, "reason": "risky_or_destructive_navigation_skipped", "manual_validation_required": True})
                continue

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=60000)
                page.wait_for_timeout(500)
            except Exception:
                continue

            crawled.append(page.url)
            page_forms, page_skipped = _record_forms(page, page.url)
            forms.extend(page_forms)
            risky_skipped.extend(page_skipped)
            _try_safe_search(page)
            links, page_external = _discover_links(page, page.url, allowed_hosts)
            external.extend(page_external)
            for link in links:
                link_url = _norm_url(link["url"])
                if link_url not in seen and _is_safe_navigation(link_url, link.get("text", "")):
                    queued.append(link)
                elif is_risky_action(f"{link_url} {link.get('text', '')}"):
                    risky_skipped.append({"url": link_url, "reason": "risky_link_skipped", "manual_validation_required": True})
            time.sleep(rate_limit)
        context.close()

    _merge_external(external)
    write_json("outputs/authenticated_crawl_urls.json", crawled)
    write_json("outputs/forms_discovered.json", forms)
    summary = {
        "target_url": target_url,
        "har_path": har_path,
        "total_urls_crawled": len(crawled),
        "total_forms_discovered": len(forms),
        "risky_actions_skipped": risky_skipped,
        "allowed_hosts": allowed_hosts,
    }
    write_json("outputs/authenticated_crawl_summary.json", summary)
    return summary
