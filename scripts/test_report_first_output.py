from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.report.html_dashboard_generator import generate_dashboard
from agent.report.json_writer import write_json


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        write_json("outputs/dynamic_allowed_hosts.json", {"root_domain": "example.com", "allowed_hosts": ["app.example.com"], "allowed_urls": ["https://app.example.com"]})
        write_json("outputs/discovered_subdomains.json", [{"hostname": "app.example.com", "source": "target_input"}])
        write_json("outputs/live_hosts.json", [{"hostname": "app.example.com", "url": "https://app.example.com", "status_code": 200, "title": "App", "webserver": "nginx", "tech": []}])
        write_json("outputs/endpoints.json", ["https://app.example.com/login", "https://app.example.com/api/orders?id=123"])
        write_json("outputs/auth_endpoints.json", ["https://app.example.com/login"])
        write_json("outputs/security_headers.json", {"hosts": [], "findings": []})
        write_json("outputs/technology_fingerprint.json", {"hosts": [], "note": "test"})
        write_json("outputs/external_dependencies.json", [{"url": "https://cdn.example.net/lib.js", "hostname": "cdn.example.net", "reason": "outside_dynamic_scope", "scanned": False}])
        write_json(
            "outputs/potential_findings.json",
            [
                {
                    "title": "Potential IDOR/BOLA",
                    "type": "BOLA/IDOR",
                    "severity": "Medium",
                    "confidence": "Medium",
                    "url": "https://app.example.com/api/orders?id=123",
                    "evidence": "Object identifier observed.",
                    "recommendation": "Validate with two authorized test users.",
                    "owasp_web": "A01 Broken Access Control",
                    "owasp_api": "API1 Broken Object Property Level Authorization",
                    "status": "Potential",
                    "manual_validation_required": True,
                    "testing_methodology": "black_box",
                    "evidence_source": "Authenticated Browser Crawl",
                    "black_box_limitations": "External evidence only.",
                    "safe_testing_note": "Manual validation only.",
                }
            ],
        )

        result = generate_dashboard({}, "https://app.example.com", "Pre-Launch Black Box Testing")
        report = Path(result["html"])
        check(report == Path("reports/assessment.html"), "primary report path is assessment.html")
        check(report.exists(), "assessment report generated")
        content = report.read_text(encoding="utf-8")
        check("Executive Summary" in content, "executive summary present")
        check("External Dependencies Observed" in content, "external dependency section present")
        check("Potential IDOR/BOLA" in content, "potential alert present")
        check("Manual Validation Queue" in content, "manual validation queue present")

    print("report_first_output tests passed")


if __name__ == "__main__":
    main()
