from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.report.asset_inventory_builder import build_asset_inventory
from agent.report.json_writer import write_json


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json(
            "outputs/live_hosts.json",
            [{"hostname": "app.example.com", "url": "https://app.example.com", "status_code": 200, "title": "App", "webserver": "nginx", "tech": ["React"]}],
        )
        write_json(
            "outputs/technology_fingerprint.json",
            {
                "hosts": [
                    {
                        "target": "https://app.example.com",
                        "final_url": "https://app.example.com",
                        "headers": {"server": "cloudflare"},
                        "detected": [{"technology": "React"}, {"technology": "Cloudflare"}],
                    }
                ]
            },
        )
        write_json("outputs/endpoints.json", ["https://app.example.com/login", "https://app.example.com/api/orders", "https://app.example.com/about"])
        write_json("outputs/auth_endpoints.json", ["https://app.example.com/login"])
        write_json("outputs/endpoint_classification.json", [{"url": "https://app.example.com/api/orders", "method": "GET", "classification": "api"}])

        inventory = build_asset_inventory()
        check(len(inventory["assets"]) == 1, "one asset built")
        asset = inventory["assets"][0]
        check("Cloudflare" in asset["cdn_waf"], "CDN/WAF detected")
        check("React" in asset["technologies"], "technology preserved")
        check(len(inventory["important_endpoints"]) == 2, "important endpoints filtered")

    print("asset_inventory_builder tests passed")


if __name__ == "__main__":
    main()
