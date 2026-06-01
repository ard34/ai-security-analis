from __future__ import annotations

from core.execution import ExecutionEngine


def fetch_security_headers(url: str, engine: ExecutionEngine) -> dict[str, object]:
    response = engine.http_request(url, method="HEAD")
    return {"url": response["url"], "status": response["status"], "headers": response["headers"]}

