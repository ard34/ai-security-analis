from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")


class ScopeError(ValueError):
    pass


def _host_from_target(target: str) -> str:
    raw = target.strip()
    if not raw:
        raise ScopeError("target is empty")
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="https")
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise ScopeError("only http and https URLs are supported")
    host = parsed.hostname or raw
    return host.strip("[]").lower().rstrip(".")


def normalize_host(target: str) -> str:
    host = _host_from_target(target)
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError("target host cannot be normalized") from exc
    if ascii_host.startswith("xn--") or ".xn--" in ascii_host:
        raise ScopeError("punycode/lookalike domains are blocked")
    return ascii_host


def is_private_or_local(host: str) -> bool:
    lowered = host.lower()
    if lowered in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved


def validate_public_host(target: str, *, allow_private: bool = False) -> str:
    host = normalize_host(target)
    if is_private_or_local(host) and not allow_private:
        raise ScopeError("localhost and private IP targets are blocked by default")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not DOMAIN_RE.match(host):
        raise ScopeError("invalid domain syntax")
    return host


def is_subdomain_or_equal(host: str, allowed_domain: str) -> bool:
    host = normalize_host(host)
    allowed = normalize_host(allowed_domain)
    return host == allowed or host.endswith(f".{allowed}")


@dataclass(slots=True)
class Scope:
    allowed_targets: list[str]
    allow_private_targets: bool = False
    normalized_targets: list[str] = field(init=False)

    def __post_init__(self) -> None:
        self.normalized_targets = [
            validate_public_host(item, allow_private=self.allow_private_targets) for item in self.allowed_targets
        ]

    def contains(self, target: str) -> bool:
        host = validate_public_host(target, allow_private=self.allow_private_targets)
        for allowed in self.normalized_targets:
            if host == allowed:
                return True
            try:
                ipaddress.ip_address(host)
                continue
            except ValueError:
                if is_subdomain_or_equal(host, allowed):
                    return True
        return False

    def require_in_scope(self, target: str) -> str:
        host = validate_public_host(target, allow_private=self.allow_private_targets)
        if not self.contains(host):
            raise ScopeError("target is out of scope")
        return host

