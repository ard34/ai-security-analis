from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse
import urllib.error
import urllib.request

from core.execution import (
    ExecutionPolicy,
    SafeExecutionContext,
    create_execution_decision,
    enforce_scope_before_action,
)
from core.logging import redact_sensitive_data


ALLOWED_HTTP_METHODS = {"GET", "HEAD"}
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}
DEFAULT_USER_AGENT = "AI-Security-Analyst/0.1 Authorized-Assessment"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass(frozen=True)
class SafeHTTPRequest:
    method: str
    url: str
    allowed_domains: list[str]
    allowed_ips: list[str] = field(default_factory=list)
    scan_id: str = "manual"
    scan_mode: str = "safe"
    max_redirects: int = 3
    max_body_bytes: int = 262144
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class SafeHTTPResponse:
    url: str
    final_url: str | None
    status_code: int | None
    headers: dict[str, str]
    body_sample: str
    elapsed_ms: int
    error: str | None
    in_scope: bool
    commands_executed: list[str] = field(default_factory=list)
    audit_events: list[dict[str, Any]] = field(default_factory=list)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def normalize_url(url: str) -> str:
    raw = str(url or "").strip()
    if not raw:
        raise ValueError("URL must be non-empty.")
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https.")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname.")
    netloc = parsed.hostname.lower()
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are not allowed.")
    return urlunparse((scheme, netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def extract_hostname(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    if not parsed.hostname:
        raise ValueError("URL must include a hostname.")
    return parsed.hostname.lower()


def validate_http_method(method: str) -> str:
    normalized = str(method or "").strip().upper()
    if normalized not in ALLOWED_HTTP_METHODS:
        raise ValueError("Only GET and HEAD are allowed by the Safe HTTP Client.")
    return normalized


def filter_sensitive_headers(headers: dict[str, str] | None) -> dict[str, str]:
    filtered: dict[str, str] = {}
    for key, value in dict(headers or {}).items():
        name = str(key or "").strip()
        if not name or name.lower() in SENSITIVE_HEADERS:
            continue
        filtered[name] = str(redact_sensitive_data(value))
    if not any(name.lower() == "user-agent" for name in filtered):
        filtered["User-Agent"] = DEFAULT_USER_AGENT
    return filtered


def is_redirect_in_scope(
    redirect_url: str,
    allowed_domains: list[str],
    allowed_ips: list[str] | None = None,
) -> bool:
    try:
        host = extract_hostname(redirect_url)
    except ValueError:
        return False
    return enforce_scope_before_action(host, allowed_domains, allowed_ips).allowed


def build_http_execution_context(
    request: SafeHTTPRequest,
    allow_network: bool = False,
) -> SafeExecutionContext:
    method = validate_http_method(request.method)
    host = extract_hostname(request.url)
    return SafeExecutionContext(
        scan_id=request.scan_id,
        target=host,
        allowed_domains=list(request.allowed_domains or []),
        allowed_ips=list(request.allowed_ips or []),
        scan_mode=request.scan_mode,
        policy=ExecutionPolicy(allow_network=allow_network, allowed_methods=(method,)),
        metadata={"component": "safe_http_client", "method": method, "url": normalize_url(request.url)},
    )


def _response_status(response: Any) -> int | None:
    return getattr(response, "status", None) or getattr(response, "code", None)


def _response_headers(response: Any) -> dict[str, str]:
    headers = getattr(response, "headers", {}) or {}
    if hasattr(headers, "items"):
        return {str(key): str(value) for key, value in headers.items()}
    return {}


def _open(opener: Any, request: urllib.request.Request, timeout: float) -> Any:
    return opener.open(request, timeout=timeout)


def _build_opener() -> Any:
    return urllib.request.build_opener(_NoRedirectHandler)


def perform_safe_http_request(
    request: SafeHTTPRequest,
    allow_network: bool = False,
    opener: Any | None = None,
) -> SafeHTTPResponse:
    started = monotonic()
    audit_events: list[dict[str, Any]] = []
    normalized_url = ""
    try:
        method = validate_http_method(request.method)
        normalized_url = normalize_url(request.url)
        host = extract_hostname(normalized_url)
        scope_decision = enforce_scope_before_action(host, request.allowed_domains, request.allowed_ips)
        if not scope_decision.allowed:
            return _http_response(request.url, None, None, {}, "", started, scope_decision.reason, False, audit_events)

        context = build_http_execution_context(request, allow_network=allow_network)
        action = "network:http_get" if method == "GET" else "network:http_head"
        decision = create_execution_decision(action, host, context, metadata={"url": normalized_url, "method": method})
        if decision.audit_event:
            audit_events.append(decision.audit_event)
        if not decision.allowed:
            return _http_response(normalized_url, None, None, {}, "", started, decision.reason, True, audit_events)

        active_opener = opener or _build_opener()
        current_url = normalized_url
        headers = filter_sensitive_headers(request.headers)
        redirects_seen = 0
        while True:
            urllib_request = urllib.request.Request(current_url, headers=headers, method=method)
            try:
                response = _open(active_opener, urllib_request, timeout=context.timeout.total_timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            status = _response_status(response)
            response_headers = _response_headers(response)
            if status in REDIRECT_STATUSES and response_headers.get("Location"):
                if redirects_seen >= request.max_redirects:
                    return _http_response(normalized_url, current_url, status, response_headers, "", started, "Maximum redirects exceeded.", True, audit_events)
                next_url = normalize_url(urljoin(current_url, response_headers["Location"]))
                if not is_redirect_in_scope(next_url, request.allowed_domains, request.allowed_ips):
                    return _http_response(normalized_url, next_url, status, response_headers, "", started, "Redirect target is outside authorized scope.", False, audit_events)
                current_url = next_url
                redirects_seen += 1
                continue
            body = b"" if method == "HEAD" else response.read(max(0, int(request.max_body_bytes)))
            final_url = response.geturl() if hasattr(response, "geturl") else current_url
            return _http_response(normalized_url, final_url, status, response_headers, _decode_body(body), started, None, True, audit_events)
    except Exception as exc:
        return _http_response(normalized_url or request.url, None, None, {}, "", started, str(redact_sensitive_data(str(exc))), False, audit_events)


def _decode_body(body: bytes) -> str:
    return body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body or "")


def _http_response(
    url: str,
    final_url: str | None,
    status_code: int | None,
    headers: dict[str, str],
    body_sample: str,
    started: float,
    error: str | None,
    in_scope: bool,
    audit_events: list[dict[str, Any]],
) -> SafeHTTPResponse:
    return SafeHTTPResponse(
        url=url,
        final_url=final_url,
        status_code=status_code,
        headers=redact_sensitive_data(headers),
        body_sample=str(redact_sensitive_data(body_sample)),
        elapsed_ms=max(0, int((monotonic() - started) * 1000)),
        error=str(redact_sensitive_data(error)) if error else None,
        in_scope=in_scope,
        commands_executed=[],
        audit_events=redact_sensitive_data(audit_events),
    )
