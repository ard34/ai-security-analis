from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.analysis.potential_bug_analyzer import analyze_potential_bugs
from agent.report.json_writer import write_json


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/dynamic_allowed_hosts.json", {"allowed_hosts": ["app.example.com"]})
        write_json("outputs/endpoint_classification.json", [{"url": "https://app.example.com/api/orders?id=1", "classification": "order"}])
        write_json("outputs/http_history.json", [{"method": "GET", "url": "https://app.example.com/api/orders?id=1", "status_code": 200, "request_headers": {"Cookie": "x"}, "response_headers": {"Content-Type": "application/json"}, "query_params": {"id": "1"}, "body_params": {}, "response_body_sample": "{\"order_id\":1}", "content_type": "application/json"}])
        findings = analyze_potential_bugs(evidence_source="Deep HTTP Analysis")
        check(findings, "finding generated")
        finding = findings[0]
        for key in ["endpoint", "request_summary", "response_summary", "manual_test_focus", "validation_steps", "affected_host", "observed_in"]:
            check(key in finding, f"{key} present")
    print("evidence_based_findings tests passed")


if __name__ == "__main__":
    main()
