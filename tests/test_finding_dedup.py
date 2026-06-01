from core.finding_dedup import deduplicate_findings
from core.models import Finding


def test_deduplicate_findings():
    findings = [Finding(title="A", severity="low"), Finding(title="A", severity="LOW")]
    assert len(deduplicate_findings(findings)) == 1

