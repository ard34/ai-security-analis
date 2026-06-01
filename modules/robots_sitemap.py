from __future__ import annotations

from urllib.parse import urljoin

from core.execution import ExecutionEngine


def fetch_robots_and_sitemap(base_url: str, engine: ExecutionEngine) -> dict[str, object]:
    results: dict[str, object] = {}
    for path in ("/robots.txt", "/sitemap.xml"):
        url = urljoin(base_url, path)
        response = engine.http_request(url, method="GET")
        results[path] = {
            "url": url,
            "status": response.get("status"),
            "body_preview": str(response.get("body", ""))[:5000],
        }
    return results

