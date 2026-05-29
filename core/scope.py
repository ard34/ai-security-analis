from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import ipaddress
import re
from urllib.parse import urlparse


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScopeValidationResult:
    allowed: bool
    normalized_target: str | None
    reason: str


def _normalize_host(value: str) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if any(char.isspace() for char in raw):
        return None

    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    host = parsed.hostname
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    if not host:
        return None
    if host.startswith("[") or host.endswith("]"):
        host = host.strip("[]")
    return host


def _normalize_domain(value: str) -> str | None:
    host = _normalize_host(value)
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(host):
        return None
    return host


def _normalize_ip(value: str) -> str | None:
    host = _normalize_host(value)
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def normalize_target(value: str) -> str | None:
    return _normalize_ip(value) or _normalize_domain(value)


def _is_localhost(host: str) -> bool:
    return host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost")


def _is_domain_in_scope(host: str, allowed_domain: str) -> bool:
    return host == allowed_domain or host.endswith(f".{allowed_domain}")


def _matches_denied_pattern(host: str, denied_patterns: list[str] | None) -> str | None:
    for pattern in denied_patterns or []:
        normalized = str(pattern or "").strip().lower()
        if not normalized:
            continue
        try:
            if re.search(normalized, host, flags=re.IGNORECASE):
                return pattern
        except re.error:
            if fnmatch.fnmatch(host, normalized):
                return pattern
    return None


def validate_scope(
    target: str,
    allowed_domains: list[str] | None = None,
    allowed_ips: list[str] | None = None,
    denied_patterns: list[str] | None = None,
) -> ScopeValidationResult:
    """Validate a target using only local parsing, never network requests."""

    normalized = normalize_target(target)
    if not normalized:
        return ScopeValidationResult(False, None, "Target is empty or malformed.")

    denied = _matches_denied_pattern(normalized, denied_patterns)
    if denied:
        return ScopeValidationResult(False, normalized, f"Target matches denied pattern: {denied}")

    if _is_localhost(normalized):
        return ScopeValidationResult(False, normalized, "Localhost targets are blocked by default.")

    allowed_ip_set = {ip for item in allowed_ips or [] if (ip := _normalize_ip(item))}
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        ip = None

    if ip is not None:
        if str(ip) in allowed_ip_set:
            return ScopeValidationResult(True, normalized, "Target IP is explicitly authorized.")
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return ScopeValidationResult(False, normalized, "Local, private, link-local, and reserved IP targets are blocked by default.")
        return ScopeValidationResult(False, normalized, "Public IP target is not explicitly authorized.")

    if not _HOSTNAME_RE.fullmatch(normalized):
        return ScopeValidationResult(False, normalized, "Target hostname is malformed.")

    allowed = [domain for item in allowed_domains or [] if (domain := _normalize_domain(item))]
    if not allowed:
        return ScopeValidationResult(False, normalized, "No authorized domains were provided.")

    for domain in allowed:
        if normalized == domain:
            return ScopeValidationResult(True, normalized, "Target is an exact authorized domain match.")
        if _is_domain_in_scope(normalized, domain):
            return ScopeValidationResult(True, normalized, "Target is a valid subdomain of an authorized domain.")

    return ScopeValidationResult(False, normalized, "Target is outside the authorized scope.")
