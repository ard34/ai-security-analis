from __future__ import annotations

from io import BytesIO

from core.models import ScanResult
from reporting.html_report import render_html_report


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
        if y < 48:
            pdf.showPage()
            y = height - 48
    pdf.save()
    return buffer.getvalue()

