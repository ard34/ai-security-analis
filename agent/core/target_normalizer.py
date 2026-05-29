from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from agent.core.domain_input_normalizer import normalize_domain_input


SUBDOMAIN_RECON_ASSESSMENTS = {
    "Pre-Launch Black Box Testing",
    "Enterprise Authorized Testing",
    "Public Bug Bounty Scope",
}


@dataclass
class NormalizedTarget:
    input: str
    normalized_url: str
    hostname: str
    registered_domain: str
    target_kind: str
    direct_scope: bool
    preserve_port: bool
    subfinder_allowed: bool
    notes: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _with_default_scheme(value: str) -> str:
    return value if "://" in value else f"https://{value}"


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def normalize_target(target: str, assessment_type: str = "Pre-Launch Black Box Testing") -> NormalizedTarget:
    domain = normalize_domain_input(target)
    raw = str(domain["input"])
    hostname = str(domain["hostname"])
    target_type = str(domain["target_type"])
    registered_domain = str(domain["target_domain"]) if target_type in {"localhost", "ip"} else str(domain["root_domain"])
    normalized_url = str(domain.get("base_url") or domain["base_https_url"])
    target_kind = "subdomain" if target_type == "domain" and hostname != registered_domain else target_type
    direct_scope = target_kind in {"localhost", "ip"}
    subfinder_allowed = bool(domain["subdomain_recon_enabled"]) and assessment_type in SUBDOMAIN_RECON_ASSESSMENTS

    notes = [str(note) for note in domain.get("notes", []) if note]
    parsed = urlparse(_with_default_scheme(raw))
    if parsed.fragment and "URL fragment stripped." not in notes:
        notes.append("URL fragment stripped.")
    if direct_scope:
        notes.append("Direct target scope; subdomain discovery skipped.")
    elif hostname != registered_domain:
        notes.append("Input subdomain included; registered domain derived for optional subdomain discovery.")
    elif not subfinder_allowed:
        notes.append("Subdomain discovery disabled for this assessment type.")

    return NormalizedTarget(
        input=target,
        normalized_url=normalized_url,
        hostname=hostname,
        registered_domain=registered_domain,
        target_kind=target_kind,
        direct_scope=direct_scope,
        preserve_port=bool(parsed.port),
        subfinder_allowed=subfinder_allowed,
        notes=notes,
    )
