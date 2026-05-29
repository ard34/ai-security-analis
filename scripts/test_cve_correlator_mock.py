from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.analysis.cve_correlator import correlate_cves
from agent.report.json_writer import write_json


def main() -> None:
    nvd_mock = [{
        "cve": {
            "id": "CVE-2024-0001",
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Mock nginx issue"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
            "references": {"referenceData": [{"url": "https://example.test/advisory"}]},
        }
    }]
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/detected_products.json", [{"product": "nginx", "version": "1.18.0", "host": "app.test", "url": "https://app.test", "source": "httpx/header"}])
        with patch("agent.analysis.cve_correlator.query_nvd", return_value=nvd_mock), patch("agent.analysis.cve_correlator.query_osv", return_value=[]):
            results = correlate_cves({"cve": {"max_results_per_product": 20}})
        assert results
        assert results[0]["cve_id"] == "CVE-2024-0001"
        assert results[0]["status"] == "Potential CVE Correlation"
        assert results[0]["manual_validation_required"] is True
    print("ok")


if __name__ == "__main__":
    main()
