from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.app import _technology_names, summarize_recon_data


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    data = {
        "subdomains_all_sources": [{"hostname": "app.example.com"}],
        "discovered_subdomains": [],
        "dns_validated_hosts": [{"hostname": "app.example.com", "ips": ["192.0.2.10"]}],
        "live_hosts": [{"hostname": "app.example.com", "technologies": ["React"]}],
        "open_ports": [{"port": 443}],
        "services": [{"protocol": "tcp", "service": "https"}],
        "technologies": [{"host": "app.example.com", "detected": [{"technology": "nginx"}]}],
        "important_endpoints": [{"url": "https://app.example.com/login"}],
        "endpoints": [],
    }
    metrics = summarize_recon_data(data)
    check(metrics["Hostnames"] == 1, "hostname count")
    check(metrics["IP Addresses"] == 1, "ip count")
    check(metrics["Technologies"] == 2, "technology count")
    check(_technology_names(data["technologies"], data["live_hosts"]) == {"React", "nginx"}, "technology names")
    print("dashboard_layout_helpers tests passed")


if __name__ == "__main__":
    main()
