from __future__ import annotations

from urllib.parse import urlparse

from agent.report.json_writer import read_json, write_json


def classify_endpoint(entry: dict[str, object]) -> str:
    url = str(entry.get("url", "")).lower()
    path = urlparse(url).path
    content_type = str(entry.get("content_type", "")).lower()
    params = " ".join((entry.get("query_params") or {}).keys()).lower() if isinstance(entry.get("query_params"), dict) else ""
    body = str(entry.get("request_body_sample", "")).lower()
    haystack = f"{path} {params} {body} {content_type}"
    rules = [
        ("auth", ["login", "signin", "logout", "oauth", "sso"]),
        ("register", ["register", "signup", "create-account"]),
        ("profile", ["profile", "me", "user"]),
        ("account", ["account"]),
        ("settings", ["settings", "preferences"]),
        ("order", ["order", "cart", "checkout"]),
        ("invoice", ["invoice", "billing"]),
        ("payment", ["payment", "stripe", "paypal"]),
        ("admin-like", ["admin", "manage", "role", "users"]),
        ("file-upload", ["upload", "multipart/form-data"]),
        ("file-download", ["download", "export"]),
        ("api", ["/api/", "application/json"]),
        ("search", ["search", "query", "filter", "q "]),
    ]
    for label, needles in rules:
        if any(needle in haystack for needle in needles):
            return label
    return "unknown"


def classify_history(history_path: str = "outputs/http_history.json") -> list[dict[str, object]]:
    history = read_json(history_path, default=[]) or []
    classified = [{"url": entry.get("url"), "method": entry.get("method"), "classification": classify_endpoint(entry)} for entry in history]
    write_json("outputs/endpoint_classification.json", classified)
    return classified
