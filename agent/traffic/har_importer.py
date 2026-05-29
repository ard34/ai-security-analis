from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from agent.core.scope_validator import get_hostname, is_allowed_url, load_dynamic_allowed_hosts
from agent.report.json_writer import read_json, write_json
from agent.traffic.sensitive_data_masker import mask_sensitive_data

BODY_LIMIT = 3000


def _headers(items: list[dict[str, str]], include_sensitive: bool = True) -> dict[str, str]:
    headers = {}
    for item in items:
        name = item.get("name", "")
        value = item.get("value", "")
        if not name:
            continue
        if not include_sensitive and name.lower() in {"cookie", "authorization", "set-cookie"}:
            continue
        headers[name] = value
    return headers


def _merge_external(new_items: list[dict[str, object]], path: str = "outputs/external_dependencies.json") -> None:
    existing = read_json(path, default=[]) or []
    merged = {str(item.get("url")): item for item in existing if item.get("url")}
    for item in new_items:
        merged.setdefault(str(item.get("url")), item)
    write_json(path, list(merged.values()))


def _path_params(url: str) -> list[str]:
    return [part for part in urlparse(url).path.split("/") if part and (part.isdigit() or "-" in part)]


def _body_params(request: dict[str, object]) -> dict[str, object]:
    post_data = request.get("postData", {}) if isinstance(request.get("postData"), dict) else {}
    params = post_data.get("params", [])
    if isinstance(params, list) and params:
        return {str(item.get("name")): item.get("value", "") for item in params if item.get("name")}
    text = str(post_data.get("text", ""))
    mime = str(post_data.get("mimeType", "")).lower()
    if "json" in mime and text:
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {"json_body": parsed}
        except json.JSONDecodeError:
            return {}
    if "x-www-form-urlencoded" in mime and text:
        return dict(parse_qsl(text, keep_blank_values=True))
    return {}


def import_har(
    har_path: str = "tmp/burp_history.har",
    output_path: str = "outputs/http_history.json",
    allowed_hosts: list[str] | None = None,
) -> list[dict[str, object]]:
    dynamic_allowed_hosts = allowed_hosts or load_dynamic_allowed_hosts()
    if not dynamic_allowed_hosts:
        raise ValueError("Dynamic allowed hosts not found. Build dynamic scope before importing HAR.")

    path = Path(har_path)
    if not path.exists():
        raise FileNotFoundError(f"HAR file not found: {path}")
    har = json.loads(path.read_text(encoding="utf-8"))
    entries = har.get("log", {}).get("entries", [])
    parsed_entries = []
    external_entries = []

    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        try:
            hostname = get_hostname(url)
        except ValueError:
            continue

        if not is_allowed_url(url, dynamic_allowed_hosts):
            external_entries.append(
                {
                    "url": url,
                    "hostname": hostname,
                    "reason": "outside_dynamic_scope_from_har",
                    "scanned": False,
                    "analyzed": False,
                    "method": request.get("method", ""),
                    "status_code": response.get("status"),
                    "request_headers": _headers(request.get("headers", []), include_sensitive=False),
                    "response_headers": _headers(response.get("headers", []), include_sensitive=False),
                }
            )
            continue

        post_data = request.get("postData", {}).get("text", "")[:BODY_LIMIT]
        response_text = response.get("content", {}).get("text", "")[:BODY_LIMIT]
        item = {
            "method": request.get("method", ""),
            "url": url,
            "hostname": hostname,
            "status_code": response.get("status"),
            "request_headers": _headers(request.get("headers", [])),
            "response_headers": _headers(response.get("headers", [])),
            "query_params": dict(parse_qsl(urlparse(url).query, keep_blank_values=True)),
            "path_params": _path_params(url),
            "body_params": _body_params(request),
            "request_body_sample": post_data,
            "response_body_sample": response_text,
            "content_type": response.get("content", {}).get("mimeType", ""),
        }
        parsed_entries.append(mask_sensitive_data(item))

    write_json(output_path, parsed_entries)
    _merge_external(external_entries)
    return parsed_entries
