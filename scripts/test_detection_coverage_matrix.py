from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.analysis.detection_coverage_matrix import build_detection_coverage_matrix
from agent.report.json_writer import write_json


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/owasp_mapping.json", [{"owasp_web_id": "A01", "owasp_api_id": "API1"}])
        rows = build_detection_coverage_matrix()
        assert len(rows) == 20
        a01 = next(item for item in rows if str(item["owasp_category"]).startswith("A01"))
        api1 = next(item for item in rows if str(item["owasp_category"]).startswith("API1"))
        assert a01["findings_count"] == 1
        assert api1["findings_count"] == 1
        assert a01["requires_manual_validation"] is True
    print("ok")


if __name__ == "__main__":
    main()
