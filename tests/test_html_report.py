from core.models import Evidence, Finding, ScanResult
from reporting.html_report import render_html_report


def test_html_report_escapes_content():
    result = ScanResult(target="<x>", workflow="type1_source")
    result.findings.append(Finding(title="<script>"))
    result.evidence.append(Evidence(source="s", content="<secret>"))
    html = render_html_report(result)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html

