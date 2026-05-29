from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse


def _strip_host(value: str) -> str:
    return value.lower().strip().strip(".")


def get_hostname(url_or_host: str) -> str:
    value = url_or_host.strip()
    parsed = urlparse(value if "://" in value else f"//{value}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Invalid URL or missing hostname: {url_or_host}")
    return _strip_host(hostname)


def get_registered_domain(url_or_host: str) -> str:
    hostname = get_hostname(url_or_host)
    try:
        import tldextract

        extracted = tldextract.TLDExtract(cache_dir=None)(hostname)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
    except Exception:
        pass

    parts = hostname.split(".")
    if len(parts) < 2:
        return hostname
    return ".".join(parts[-2:])


def is_same_registered_domain(hostname: str, root_domain: str) -> bool:
    return get_registered_domain(hostname) == get_registered_domain(root_domain)


def is_allowed_host(hostname: str, dynamic_allowed_hosts: list[str]) -> bool:
    normalized = {_strip_host(host) for host in dynamic_allowed_hosts}
    return _strip_host(hostname) in normalized


def is_allowed_url(url: str, dynamic_allowed_hosts: list[str]) -> bool:
    return is_allowed_host(get_hostname(url), dynamic_allowed_hosts)


def enforce_url_scope(url: str, dynamic_allowed_hosts: list[str]) -> None:
    if not dynamic_allowed_hosts:
        raise ValueError("Scope validation failed: dynamic allowed hosts is empty.")
    if not is_allowed_url(url, dynamic_allowed_hosts):
        raise ValueError(
            f"Scope validation failed: {url} is outside dynamic allowed hosts. "
            "Subdomains must be discovered and explicitly included; wildcard scope is disabled."
        )


def filter_allowed_urls(urls: list[str], dynamic_allowed_hosts: list[str]) -> list[str]:
    allowed: list[str] = []
    seen = set()
    for url in urls:
        try:
            if is_allowed_url(url, dynamic_allowed_hosts) and url not in seen:
                allowed.append(url)
                seen.add(url)
        except ValueError:
            continue
    return allowed


def split_internal_external_urls(urls: list[str], dynamic_allowed_hosts: list[str]) -> tuple[list[str], list[dict[str, object]]]:
    internal: list[str] = []
    external: list[dict[str, object]] = []
    seen_internal = set()
    seen_external = set()
    for url in urls:
        try:
            hostname = get_hostname(url)
        except ValueError:
            continue
        if is_allowed_host(hostname, dynamic_allowed_hosts):
            if url not in seen_internal:
                internal.append(url)
                seen_internal.add(url)
        elif url not in seen_external:
            external.append({"url": url, "hostname": hostname, "reason": "outside_dynamic_scope", "scanned": False, "analyzed": False})
            seen_external.add(url)
    return internal, external


def load_dynamic_allowed_hosts(path: str = "outputs/dynamic_allowed_hosts.json") -> list[str]:
    scope_path = Path(path)
    if not scope_path.exists():
        return []
    data = json.loads(scope_path.read_text(encoding="utf-8"))
    hosts = data.get("allowed_hosts", [])
    return [_strip_host(str(host)) for host in hosts] if isinstance(hosts, list) else []


def fallback_allowed_hosts_from_config(config: dict[str, object]) -> list[str]:
    target = config.get("target", {}) if isinstance(config.get("target"), dict) else {}
    root = str(target.get("root_domain") or target.get("base_url") or "").strip()
    return [get_registered_domain(root)] if root else []


# Backward-compatible names used by older modules.
def is_allowed(url: str, allowed_hosts: list[str]) -> bool:
    return is_allowed_url(url, allowed_hosts)


def enforce_scope(url: str, allowed_hosts: list[str]) -> None:
    enforce_url_scope(url, allowed_hosts)
