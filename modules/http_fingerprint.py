from __future__ import annotations

from core.execution import ExecutionEngine


def fingerprint_http(url: str, engine: ExecutionEngine) -> dict[str, object]:
    response = engine.http_request(url, method="HEAD")
    headers = response.get("headers", {})
    if not isinstance(headers, dict):
        headers = {}
    return {
        "status": response.get("status"),
        "server": headers.get("Server") or headers.get("server"),
        "powered_by": headers.get("X-Powered-By") or headers.get("x-powered-by"),
        "content_type": headers.get("Content-Type") or headers.get("content-type"),
    }

