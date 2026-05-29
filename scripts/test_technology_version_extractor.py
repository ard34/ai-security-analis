from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.analysis.technology_version_extractor import extract_detected_products
from agent.report.json_writer import write_json


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/recon/live_hosts.json", [{"hostname": "app.test", "url": "https://app.test", "webserver": "nginx/1.18.0", "technologies": ["React"]}])
        write_json("outputs/recon/services.json", [{"host": "app.test", "service": "http", "product": "Apache httpd", "version": "2.4.54"}])
        products = extract_detected_products()
        assert any(item["product"] == "nginx" and item["version"] == "1.18.0" for item in products)
        assert any(item["product"] == "Apache httpd" and item["version"] == "2.4.54" for item in products)
        assert any(item["product"] == "React" and item["version"] is None for item in products)
    print("ok")


if __name__ == "__main__":
    main()
