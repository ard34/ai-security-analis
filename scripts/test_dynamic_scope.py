from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.core.dynamic_scope import build_dynamic_scope
from agent.core.scope_validator import is_allowed_url
from agent.report.json_writer import write_json


def main() -> None:
    target = "https://example.com"
    mock_discovered = [
        {"hostname": "example.com", "source": "root_domain", "same_registered_domain": True},
        {"hostname": "www.example.com", "source": "subfinder", "same_registered_domain": True},
        {"hostname": "api.example.com", "source": "subfinder", "same_registered_domain": True},
        {"hostname": "example.com.evil.com", "source": "subfinder", "same_registered_domain": False},
        {"hostname": "evil-example.com", "source": "subfinder", "same_registered_domain": False},
        {"hostname": "google.com", "source": "subfinder", "same_registered_domain": False},
    ]
    write_json("outputs/discovered_subdomains.json", mock_discovered)
    write_json("outputs/live_hosts.json", [])

    config = {
        "target": {"base_url": target, "root_domain": ""},
        "scope": {
            "mode": "dynamic_subdomain_recon",
            "include_root_domain": True,
            "include_discovered_subdomains": True,
            "require_same_registered_domain": True,
            "require_http_alive": False,
        },
    }
    scope = build_dynamic_scope(target, config)
    expected = ["api.example.com", "example.com", "www.example.com"]
    assert scope["allowed_hosts"] == expected, scope["allowed_hosts"]

    allowed = ["https://example.com", "https://api.example.com", "https://www.example.com"]
    rejected = [
        "https://admin.example.com",
        "https://example.com.evil.com",
        "https://evil-example.com",
        "https://google.com",
    ]
    for url in allowed:
        assert is_allowed_url(url, scope["allowed_hosts"]), url
    for url in rejected:
        assert not is_allowed_url(url, scope["allowed_hosts"]), url

    print("dynamic scope tests passed")


if __name__ == "__main__":
    main()
