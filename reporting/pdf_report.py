from __future__ import annotations

from io import BytesIO

from core.models import ScanResult
from reporting.html_report import VALIDATION_READY_DISCLAIMER, render_html_report


def render_pdf_report(result: ScanResult) -> bytes:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError:
        return render_html_report(result).encode("utf-8")

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 48
    pdf.drawString(48, y, "AI Security Analyst Report")
    y -= 24
    pdf.drawString(48, y, f"Workflow: {result.workflow}")
    y -= 18
    pdf.drawString(48, y, f"Target: {result.target}")
    y -= 24
    pdf.drawString(48, y, "Potential Findings:")
    y -= 18
    for finding in result.findings[:20]:
        pdf.drawString(60, y, f"- {finding.severity}: {finding.title[:90]}")
        y -= 16
        if finding.validation_status in {"logic_analyzed", "validation_ready"}:
            pdf.drawString(72, y, f"Validation: {finding.validation_status}; confidence: {finding.confidence_score}")
            y -= 16
            if finding.source_locations:
                location = finding.source_locations[0]
                pdf.drawString(72, y, f"Source: {location.get('file', '')}:{location.get('line', '')}")
                y -= 16
        if y < 48:
            pdf.showPage()
            y = height - 48
    if y < 80:
        pdf.showPage()
        y = height - 48
    pdf.drawString(48, y, VALIDATION_READY_DISCLAIMER[:110])
    pdf.save()
    return buffer.getvalue()

