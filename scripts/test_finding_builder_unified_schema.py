from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.analysis.finding_builder import build_findings
from agent.report.json_writer import write_json


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/potential_findings.json", [{"title": "Potential IDOR/BOLA", "type": "BOLA/IDOR", "url": "https://app.test/api/orders/1", "severity": "High", "confidence": "Medium", "evidence": "object id endpoint"}])
        write_json("outputs/potential_auth_session_issues.json", [{"title": "Potential Authentication Weakness", "type": "Authentication/session weakness", "endpoint": "https://app.test/login", "severity": "Medium"}])
        write_json("outputs/potential_security_misconfigurations.json", [{"title": "Potential Security Misconfiguration", "type": "Security misconfiguration", "endpoint": "https://app.test", "severity": "Low"}])
        write_json("outputs/potential_vulnerable_components.json", [{"title": "Potential Vulnerable Component", "type": "Vulnerable component", "endpoint": "https://app.test", "severity": "Medium", "related_cves": ["CVE-2024-0001"]}])
        write_json("outputs/api_top10_candidates.json", [{"title": "Potential BFLA", "type": "BFLA", "endpoint": "https://app.test/admin", "severity": "High"}])
        summary = build_findings()
        findings = summary["all_findings"]
        assert findings
        required = ["finding_id", "endpoint", "request_summary", "response_summary", "manual_test_focus", "owasp_web", "owasp_api", "cve_ids", "status", "manual_validation_required"]
        for finding in findings:
            for key in required:
                assert key in finding, (key, finding)
            assert finding["status"] == "Potential"
            assert finding["manual_validation_required"] is True
    print("ok")


if __name__ == "__main__":
    main()
