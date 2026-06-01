from core.models import ScanResult
from reporting.pdf_report import render_pdf_report


def test_pdf_report_returns_bytes():
    assert isinstance(render_pdf_report(ScanResult(target="x", workflow="w")), bytes)

