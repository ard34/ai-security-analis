from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.analysis.vulnerable_component_analyzer import analyze_vulnerable_components
from agent.report.json_writer import write_json


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/detected_products.json", [{"product": "nginx", "version": "1.18.0", "host": "app.test", "url": "https://app.test", "version_confidence": "High", "evidence": "nginx/1.18.0"}])
        write_json("outputs/cve_correlations.json", [{"detected_product": "nginx", "detected_version": "1.18.0", "affected_host": "app.test", "cve_id": "CVE-2024-0001", "cvss_score": 7.5, "severity": "High"}])
        results = analyze_vulnerable_components()
        assert results
        assert results[0]["owasp_web"].startswith("A06")
        assert results[0]["owasp_api"].startswith("API9")
        assert results[0]["related_cves"] == ["CVE-2024-0001"]
    print("ok")


if __name__ == "__main__":
    main()
