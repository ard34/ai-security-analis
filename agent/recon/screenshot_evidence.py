from __future__ import annotations

from pathlib import Path

from agent.core.scope_validator import is_allowed_url
from agent.report.json_writer import write_json


def capture_screenshots(live_hosts: list[dict[str, object]], allowed_hosts: list[str], output_dir: str = "outputs/recon/screenshots") -> list[dict[str, object]]:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    results = []
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        write_json("outputs/recon/screenshot_index.json", {"status": "skipped", "reason": str(exc), "screenshots": []})
        return []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1366, "height": 768}, ignore_https_errors=True)
            page = context.new_page()
            for host in live_hosts:
                url = str(host.get("url", ""))
                if not url or not is_allowed_url(url, allowed_hosts):
                    continue
                filename = f"{str(host.get('hostname', 'host')).replace(':', '_')}.png"
                path = str(Path(output_dir) / filename)
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    page.screenshot(path=path, full_page=True)
                    results.append({"host": host.get("hostname", ""), "url": url, "path": path, "status": "captured"})
                except Exception as exc:
                    results.append({"host": host.get("hostname", ""), "url": url, "path": path, "status": "failed", "reason": str(exc)})
            context.close()
            browser.close()
    except Exception as exc:
        write_json("outputs/recon/screenshot_index.json", {"status": "skipped_or_failed", "reason": str(exc), "screenshots": results})
        return results
    write_json("outputs/recon/screenshot_index.json", {"status": "collected", "screenshots": results})
    return results
