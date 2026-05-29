from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.recon.attack_surface_mapper import build_attack_surface
from agent.report.json_writer import write_json


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/recon/live_hosts.json", [{"hostname": "app.example.com", "url": "https://app.example.com"}])
        write_json("outputs/recon/open_ports.json", [{"host": "app.example.com", "port": 443, "service": "https"}])
        write_json("outputs/recon/services.json", [{"host": "app.example.com", "port": 443, "service": "https"}])
        write_json("outputs/recon/technologies.json", [{"host": "app.example.com", "detected": [{"technology": "React"}]}])
        write_json(
            "outputs/recon/important_endpoints.json",
            [
                {"url": "https://app.example.com/login", "hostname": "app.example.com", "category": "auth"},
                {"url": "https://app.example.com/api/orders", "hostname": "app.example.com", "category": "api"},
                {"url": "https://app.example.com/admin", "hostname": "app.example.com", "category": "admin-like"},
            ],
        )
        write_json("outputs/recon/security_headers.json", [{"host": "app.example.com", "issue_count": 2}])
        write_json("outputs/external_dependencies.json", [{"url": "https://cdn.example.net/lib.js", "hostname": "cdn.example.net"}])
        surface = build_attack_surface()
        categories = {item["category"] for item in surface}
        check("API Assets" in categories, "API category present")
        check("Authentication Surfaces" in categories, "auth category present")
        check("Third-party / External Dependencies Observed" in categories, "external category present")
        check(Path("outputs/recon/attack_surface.json").exists(), "attack surface output written")
    print("attack_surface_mapper tests passed")


if __name__ == "__main__":
    main()
