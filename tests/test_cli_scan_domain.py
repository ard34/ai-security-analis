import pytest

from cli import main
from core.assessment import Assessment, save_assessment


def test_cli_scan_domain_rejects_missing_gates(tmp_path):
    assessment_path = tmp_path / "assessment.json"
    save_assessment(Assessment("a", ["example.com"]).approve(), assessment_path)
    with pytest.raises(SystemExit):
        main(
            [
                "scan-domain",
                "--target",
                "example.com",
                "--assessment-json",
                str(assessment_path),
                "--audit-log-path",
                str(tmp_path / "a.jsonl"),
            ]
        )


def test_cli_scan_domain_rejects_unapproved(tmp_path):
    assessment_path = tmp_path / "assessment.json"
    save_assessment(Assessment("a", ["example.com"]), assessment_path)
    with pytest.raises(SystemExit):
        main([
            "scan-domain",
            "--target",
            "example.com",
            "--assessment-json",
            str(assessment_path),
            "--allow-network",
            "--confirm-safe-live",
            "--audit-log-path",
            str(tmp_path / "a.jsonl"),
        ])

