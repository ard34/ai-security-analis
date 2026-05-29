from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from agent.core.scope_validator import get_registered_domain, is_same_registered_domain
from agent.core.target_normalizer import normalize_target
from agent.recon.http_probe import probe_http
from agent.recon.subdomain_recon import discover_subdomains, derive_root_domain
from agent.report.json_writer import read_json, write_json


def _scope_config(config: dict[str, object]) -> dict[str, object]:
    return config.get("scope", {}) if isinstance(config.get("scope"), dict) else {}


def _target_config(config: dict[str, object]) -> dict[str, object]:
    return config.get("target", {}) if isinstance(config.get("target"), dict) else {}


def ensure_dynamic_scope(target: str, config: dict[str, object], force: bool = False) -> dict[str, object]:
    scope_path = Path("outputs/dynamic_allowed_hosts.json")
    if scope_path.exists() and not force:
        return read_json(scope_path, default={}) or {}

    assessment = config.get("assessment", {}) if isinstance(config.get("assessment"), dict) else {}
    normalized = normalize_target(target, str(assessment.get("type") or assessment.get("profile") or "Pre-Launch Black Box Testing"))
    write_json("outputs/target_normalized.json", normalized.to_dict())

    scope_config = _scope_config(config)
    original_include_discovered = scope_config.get("include_discovered_subdomains", True)
    if not normalized.subfinder_allowed:
        scope_config["include_discovered_subdomains"] = False

    discover_subdomains(target, config)
    if bool(_scope_config(config).get("require_http_alive", True)):
        probe_http(config)
    scope_config["include_discovered_subdomains"] = original_include_discovered
    return build_dynamic_scope(target, config)


def build_dynamic_scope(target: str, config: dict[str, object]) -> dict[str, object]:
    scope_config = _scope_config(config)
    target_config = _target_config(config)
    assessment = config.get("assessment", {}) if isinstance(config.get("assessment"), dict) else {}
    normalized = normalize_target(target, str(assessment.get("type") or assessment.get("profile") or "Pre-Launch Black Box Testing"))
    root_domain = normalized.registered_domain if normalized.direct_scope else derive_root_domain(target, str(target_config.get("root_domain", "")))
    require_alive = bool(scope_config.get("require_http_alive", True))
    discovered = read_json("outputs/discovered_subdomains.json", default=[]) or []
    live_hosts = read_json("outputs/live_hosts.json", default=[]) or []

    allowed: dict[str, str] = {}
    seen = set()

    if normalized.direct_scope and not live_hosts:
        candidates = [(normalized.hostname, normalized.normalized_url)]
    elif require_alive:
        candidates = [(str(item.get("hostname", "")).lower().strip("."), str(item.get("url", ""))) for item in live_hosts]
    else:
        candidates = [(str(item.get("hostname", "")).lower().strip("."), "") for item in discovered]

    if bool(scope_config.get("include_root_domain", True)) and not require_alive and not normalized.direct_scope:
        candidates.append((root_domain, ""))

    for hostname, url in candidates:
        if not hostname or hostname in seen:
            continue
        if normalized.direct_scope:
            in_scope = hostname == normalized.hostname
        else:
            in_scope = is_same_registered_domain(hostname, root_domain)
        if not in_scope:
            continue
        seen.add(hostname)
        if url:
            allowed[hostname] = url
        else:
            scheme = urlparse(target).scheme or "https"
            allowed[hostname] = f"{scheme}://{hostname}"

    data = {
        "root_domain": get_registered_domain(root_domain),
        "mode": scope_config.get("mode", "dynamic_subdomain_recon"),
        "allowed_hosts": sorted(allowed),
        "allowed_urls": [allowed[host] for host in sorted(allowed)],
        "source_files": ["outputs/discovered_subdomains.json", "outputs/live_hosts.json"],
    }
    write_json("outputs/dynamic_allowed_hosts.json", data)
    return data
