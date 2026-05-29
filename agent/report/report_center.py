from __future__ import annotations

from pathlib import Path
from typing import Any

from agent.report.html_dashboard_generator import generate_dashboard
from agent.report.json_writer import read_json
from agent.report.recon_html_report import generate_recon_report
from agent.report.zap_html_report import generate_zap_report


def run_detection_enrichment(config: dict[str, object] | None = None) -> dict[str, int]:
    """Refresh non-intrusive detection outputs before report generation."""
    config = config or {}
    from agent.analysis.api_top10_analyzer import analyze_api_top10
    from agent.analysis.auth_session_analyzer import analyze_auth_session
    from agent.analysis.cve_correlator import correlate_cves
    from agent.analysis.detection_coverage_matrix import build_detection_coverage_matrix
    from agent.analysis.finding_builder import build_findings
    from agent.analysis.owasp_mapping_engine import map_findings
    from agent.analysis.security_misconfiguration_analyzer import analyze_security_misconfigurations
    from agent.analysis.technology_version_extractor import extract_detected_products
    from agent.analysis.vulnerable_component_analyzer import analyze_vulnerable_components

    products = extract_detected_products()
    cves = correlate_cves(config)
    components = analyze_vulnerable_components()
    auth = analyze_auth_session()
    misconfigs = analyze_security_misconfigurations()
    api = analyze_api_top10()
    findings = build_findings().get("all_findings", [])
    mappings = map_findings()
    coverage = build_detection_coverage_matrix()
    return {
        "detected_products": len(products),
        "cve_correlations": len(cves),
        "vulnerable_components": len(components),
        "auth_session_issues": len(auth),
        "security_misconfigurations": len(misconfigs),
        "api_top10_candidates": len(api),
        "potential_findings": len(findings) if isinstance(findings, list) else 0,
        "owasp_mappings": len(mappings),
        "coverage_categories": len(coverage),
    }


def _target(config: dict[str, object]) -> str:
    target = config.get("target", {}) if isinstance(config.get("target"), dict) else {}
    return str(target.get("base_url", ""))


def _assessment_type(config: dict[str, object]) -> str:
    assessment = config.get("assessment", {}) if isinstance(config.get("assessment"), dict) else {}
    return str(assessment.get("type") or assessment.get("profile") or "Black Box")


def generate_recon_report_html(config: dict[str, object]) -> str:
    run_detection_enrichment(config)
    summary = read_json("outputs/recon/recon_summary.json", default={}) or {}
    return str(generate_recon_report(summary, "reports/recon_report.html")["html"])


def generate_assessment_report_html(config: dict[str, object]) -> str:
    run_detection_enrichment(config)
    return str(generate_dashboard(config, _target(config), _assessment_type(config), "reports/assessment.html")["html"])


def generate_zap_report_html(config: dict[str, object]) -> str:
    return generate_zap_report("reports/zap_report.html")


def generate_executive_summary_html(config: dict[str, object]) -> str:
    recon = read_json("outputs/recon/recon_summary.json", default={}) or {}
    findings = read_json("outputs/potential_findings.json", default=[]) or []
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Ringkasan Eksekutif</title></head><body>
<h1>Ringkasan Eksekutif</h1><p>Target: {_target(config)}</p><p>Host aktif: {recon.get('total_live_hosts', 0)}</p><p>Alert potensial: {len(findings)}</p><p>Semua temuan perlu validasi manual.</p></body></html>"""
    Path("reports").mkdir(parents=True, exist_ok=True)
    Path("reports/executive_summary.html").write_text(html, encoding="utf-8")
    return "reports/executive_summary.html"


def generate_all_reports_html(config: dict[str, object]) -> dict[str, str]:
    return {
        "recon": generate_recon_report_html(config),
        "assessment": generate_assessment_report_html(config),
        "zap": generate_zap_report_html(config),
        "executive_summary": generate_executive_summary_html(config),
    }


def generate_pdf_from_html(html_path: str, pdf_path: str) -> bool:
    try:
        from weasyprint import HTML

        if not Path(html_path).exists():
            return False
        Path(pdf_path).parent.mkdir(parents=True, exist_ok=True)
        HTML(filename=html_path).write_pdf(pdf_path)
        return True
    except Exception:
        return False


def generate_all_reports_pdf(config: dict[str, object]) -> dict[str, bool]:
    htmls = {
        "recon": "reports/recon_report.html",
        "assessment": "reports/assessment.html",
        "zap": "reports/zap_report.html",
        "executive_summary": "reports/executive_summary.html",
    }
    return {key: generate_pdf_from_html(html, html.replace(".html", ".pdf")) for key, html in htmls.items()}


def get_report_status() -> dict[str, dict[str, Any]]:
    reports = {
        "Laporan Recon": ("reports/recon_report.html", "reports/recon_report.pdf"),
        "Laporan Assessment": ("reports/assessment.html", "reports/assessment.pdf"),
        "Laporan OWASP ZAP": ("reports/zap_report.html", "reports/zap_report.pdf"),
        "Ringkasan Eksekutif": ("reports/executive_summary.html", "reports/executive_summary.pdf"),
    }
    status: dict[str, dict[str, Any]] = {}
    for name, (html_path, pdf_path) in reports.items():
        html_file = Path(html_path)
        pdf_file = Path(pdf_path)
        latest = max([p.stat().st_mtime for p in [html_file, pdf_file] if p.exists()], default=0)
        from datetime import datetime

        status[name] = {
            "html_path": html_path,
            "pdf_path": pdf_path,
            "html_status": "Ada" if html_file.exists() else "Belum dibuat",
            "pdf_status": "Ada" if pdf_file.exists() else "Belum dibuat",
            "last_generated": datetime.fromtimestamp(latest).isoformat() if latest else "",
        }
    return status
