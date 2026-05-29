from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.core.target_normalizer import normalize_target


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    domain = normalize_target("example.com", "Pre-Launch Black Box Testing")
    check(domain.normalized_url == "https://example.com", "domain gets https default")
    check(domain.target_kind == "domain", "domain classified as domain")
    check(domain.registered_domain == "example.com", "registered domain derived")
    check(domain.subfinder_allowed, "subfinder allowed for authorized public domain assessment")

    subdomain = normalize_target("https://sub.example.com", "Enterprise Authorized Testing")
    check(subdomain.target_kind == "subdomain", "subdomain classified")
    check(subdomain.registered_domain == "example.com", "root domain derived for subdomain")
    check(subdomain.subfinder_allowed, "subfinder allowed for enterprise subdomain")

    ip_target = normalize_target("http://192.168.56.20", "Local Lab / Training")
    check(ip_target.target_kind == "ip", "IP classified")
    check(ip_target.direct_scope, "IP is direct scope")
    check(not ip_target.subfinder_allowed, "IP skips subfinder")

    localhost = normalize_target("http://localhost:3000/#/", "Local Lab / Training")
    check(localhost.normalized_url == "http://localhost:3000", "fragment stripped and port preserved")
    check(localhost.target_kind == "localhost", "localhost classified")
    check(localhost.preserve_port, "localhost port preserved")

    loopback = normalize_target("http://127.0.0.1:3000", "Local Lab / Training")
    check(loopback.normalized_url == "http://127.0.0.1:3000", "loopback URL preserved")
    check(loopback.direct_scope, "loopback is direct scope")

    print("target_normalizer tests passed")


if __name__ == "__main__":
    main()
