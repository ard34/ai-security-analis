from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.analysis.api_top10_analyzer import analyze_api_top10
from agent.report.json_writer import write_json


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/recon/important_endpoints.json", [
            {"url": "https://app.test/api/orders?id=1", "category": "api"},
            {"url": "https://app.test/admin/users", "category": "admin-like"},
            {"url": "https://app.test/payment/checkout", "category": "order"},
            {"url": "https://app.test/api/search?q=a", "category": "search"},
        ])
        write_json("outputs/external_dependencies.json", [{"url": "https://pay.example/sdk.js", "hostname": "pay.example"}])
        results = analyze_api_top10()
        ids = {item["api_id"] for item in results}
        assert {"API1", "API4", "API5", "API6", "API10"}.issubset(ids)
        assert all(item["manual_validation_required"] is True for item in results)
    print("ok")


if __name__ == "__main__":
    main()
