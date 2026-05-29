from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.report.feature_section_mapper import build_feature_sections
from agent.report.json_writer import write_json


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/recon/subdomains_by_source.json", {"subfinder": ["www.example.com"]})
        write_json("outputs/recon/waf_cdn.json", [{"host": "www.example.com", "provider": "Cloudflare"}])
        write_json("outputs/zap/zap_passive_alerts.json", [{"alert": "CSP Missing"}])
        write_json("outputs/potential_findings.json", [{"title": "Potential IDOR/BOLA"}])
        sections = build_feature_sections()
        check(sections["subfinder"]["summary_metrics"]["jumlah_hasil"] == 1, "subfinder mapped")
        check(sections["waf_cdn"]["summary_metrics"]["indicators"] == 1, "waf mapped")
        check(sections["zap"]["summary_metrics"]["alerts"] == 1, "zap mapped")
        check(sections["potential_bugs"]["summary_metrics"]["findings"] == 1, "potential bugs mapped")
    print("feature_section_mapper tests passed")


if __name__ == "__main__":
    main()
