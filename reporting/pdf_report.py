from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any

from reporting.html_report import SAFETY_DISCLAIMER, generate_html_report, summarize_report


class PDFReportError(ValueError):
    pass


def validate_pdf_output_path(output_path: str) -> str:
    path = Path(str(output_path or ""))
    if not str(output_path or "").strip():
        raise PDFReportError("PDF output path is required.")
    if path.suffix.lower() != ".pdf":
        raise PDFReportError("PDF output path must end with .pdf.")
    return str(path)


def ensure_parent_directory(output_path: str) -> None:
    path = Path(validate_pdf_output_path(output_path))
    path.parent.mkdir(parents=True, exist_ok=True)


def _pdf_escape(value: object) -> str:
    return str(value if value is not None else "").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _minimal_pdf_bytes(lines: list[str]) -> bytes:
    stream_lines = ["BT", "/F1 12 Tf", "50 790 Td", "14 TL"]
    for index, line in enumerate(lines):
        safe = _pdf_escape(line[:110])
        if index == 0:
            stream_lines.append(f"({safe}) Tj")
        else:
            stream_lines.append(f"T* ({safe}) Tj")
    stream_lines.append("ET")
    stream = "\n".join(stream_lines).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    pdf = BytesIO()
    pdf.write(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(pdf.tell())
        pdf.write(f"{number} 0 obj\n".encode("ascii"))
        pdf.write(obj)
        pdf.write(b"\nendobj\n")
    xref = pdf.tell()
    pdf.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.write(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return pdf.getvalue()


def _fallback_pdf_bytes(scan_result: dict[str, Any]) -> bytes:
    summary = summarize_report(scan_result)
    lines = [
        "AI Security Analyst",
        "Security Reconnaissance Report",
        f"Scan ID: {scan_result.get('scan_id', '')}",
        f"Target: {scan_result.get('target', '')}",
        f"Normalized target: {scan_result.get('normalized_target', '')}",
        f"Scan mode: {scan_result.get('scan_mode', '')}",
        f"Status: {scan_result.get('status', '')}",
        f"Started at: {scan_result.get('started_at', '')}",
        f"Ended at: {scan_result.get('ended_at', '')}",
        f"Assets count: {summary['assets_count']}",
        f"Endpoints count: {summary['endpoints_count']}",
        f"Findings count: {summary['findings_count']}",
        SAFETY_DISCLAIMER,
    ]
    return _minimal_pdf_bytes(lines)


def html_to_pdf_bytes(html: str, scan_result: dict[str, Any] | None = None) -> bytes:
    try:
        from weasyprint import HTML

        return HTML(string=html).write_pdf()
    except Exception:
        return _fallback_pdf_bytes(scan_result or {})


def generate_pdf_report(scan_result: dict[str, Any], output_path: str) -> str:
    path = validate_pdf_output_path(output_path)
    ensure_parent_directory(path)
    html = generate_html_report(scan_result)
    pdf_bytes = html_to_pdf_bytes(html, scan_result=scan_result)
    Path(path).write_bytes(pdf_bytes)
    return path

