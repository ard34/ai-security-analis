from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.analysis.owasp_mapping_engine import map_findings
from agent.report.json_writer import read_json, write_json


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/potential_findings.json", [{"finding_id": "PF-1", "title": "Potential IDOR/BOLA", "type": "BOLA/IDOR", "endpoint": "https://app.test/api/orders/1"}])
        mapped = map_findings()
        assert mapped
        assert mapped[0]["owasp_web_id"] == "A01"
        assert mapped[0]["owasp_api_id"] == "API1"
        assert read_json("outputs/owasp_mapping.json", default=[]) == mapped
    print("ok")


if __name__ == "__main__":
    main()
