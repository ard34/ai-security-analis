from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


_HOST_RE = re.compile(r"^[a-z0-9.-]+$")


def _parse_hostname(value: str) -> tuple[str, str, str]:
    candidate = value.strip().lower()
    if " " in candidate:
        raise ValueError("Target domain tidak valid. Gunakan format seperti fahram.dev")
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    if not parsed.hostname:
        raise ValueError("Target domain tidak valid. Gunakan format seperti fahram.dev")
    hostname = parsed.hostname.lower().strip(".")
    if not hostname or not _HOST_RE.match(hostname):
        raise ValueError("Target domain tidak valid. Gunakan format seperti fahram.dev")
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else ""
    netloc = parsed.netloc
    if not netloc and "://" not in candidate:
        netloc = candidate.split("/", 1)[0]
    return hostname, scheme, netloc


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _registered_domain(hostname: str) -> str:
    try:
        import tldextract

        extracted = tldextract.TLDExtract(cache_dir=None)(hostname)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
    except Exception:
        pass
    parts = hostname.split(".")
    if len(parts) < 2:
        raise ValueError("Target domain tidak valid. Gunakan format seperti fahram.dev")
    return ".".join(parts[-2:])


def normalize_domain_input(user_input: str) -> dict[str, object]:
    raw = str(user_input or "").strip()
    if not raw:
        raise ValueError("Target domain tidak valid. Gunakan format seperti fahram.dev")

    hostname, scheme, netloc = _parse_hostname(raw)
    notes: list[str] = []
    is_localhost = hostname == "localhost"
    is_ip = _is_ip(hostname)
    parsed = urlparse(raw.lower() if "://" in raw else f"//{raw.lower()}")

    if is_localhost or is_ip:
        target_type = "localhost" if is_localhost else "ip"
        selected_scheme = scheme or "http"
        authority = netloc or hostname
        base_url = f"{selected_scheme}://{authority}".rstrip("/")
        notes.append("Subdomain recon dilewati untuk target IP/local.")
        return {
            "input": raw,
            "hostname": hostname,
            "root_domain": None,
            "target_domain": hostname,
            "target_type": target_type,
            "base_url": base_url,
            "base_https_url": f"https://{authority}",
            "base_http_url": f"http://{authority}",
            "subdomain_recon_enabled": False,
            "notes": notes,
        }

    root_domain = _registered_domain(hostname[4:] if hostname.startswith("www.") else hostname)
    if "." not in root_domain or root_domain.startswith(".") or root_domain.endswith("."):
        raise ValueError("Target domain tidak valid. Gunakan format seperti fahram.dev")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or hostname != root_domain:
        notes.append(f"Input URL dinormalisasi menjadi domain utama untuk recon: {root_domain}")

    return {
        "input": raw,
        "hostname": hostname,
        "root_domain": root_domain,
        "target_domain": root_domain,
        "target_type": "domain",
        "base_https_url": f"https://{root_domain}",
        "base_http_url": f"http://{root_domain}",
        "subdomain_recon_enabled": True,
        "notes": notes,
    }
