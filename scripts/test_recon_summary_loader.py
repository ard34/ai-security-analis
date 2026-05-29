from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.report.json_writer import write_json
from ui.app import load_recon_data, summarize_recon_data


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    paths = [
        Path("outputs/recon/live_hosts.json"),
        Path("outputs/recon/dns_validated_hosts.json"),
        Path("outputs/recon/important_endpoints.json"),
    ]
    originals = {path: path.read_text(encoding="utf-8") if path.exists() else None for path in paths}
    try:
        Path("outputs/recon").mkdir(parents=True, exist_ok=True)
        write_json("outputs/recon/live_hosts.json", [{"hostname": "app.example.com", "url": "https://app.example.com"}])
        write_json("outputs/recon/dns_validated_hosts.json", [{"hostname": "app.example.com", "ip": "192.0.2.10", "resolved": True}])
        write_json("outputs/recon/important_endpoints.json", [{"url": "https://app.example.com/login"}])
        data = load_recon_data()
        metrics = summarize_recon_data(data)
        check(len(data["live_hosts"]) == 1, "live hosts loaded")
        check(metrics["Live Hosts"] == 1, "live host metric")
        check(metrics["Endpoints"] == 1, "endpoint metric")
    finally:
        for path, original in originals.items():
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(original, encoding="utf-8")
    print("recon_summary_loader tests passed")


if __name__ == "__main__":
    main()
