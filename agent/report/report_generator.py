from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agent.analysis.finding_builder import build_findings
from agent.report.json_writer import read_json


def generate_report(config: dict[str, object], target: str) -> dict[str, str]:
    from agent.report.html_dashboard_generator import generate_dashboard

    report_config = config.get("report", {}) if isinstance(config.get("report"), dict) else {}
    target_config = config.get("target", {}) if isinstance(config.get("target"), dict) else {}
    assessment_config = config.get("assessment", {}) if isinstance(config.get("assessment"), dict) else {}
    output_html = str(report_config.get("output_html", "reports/report.html"))
    output_pdf = str(report_config.get("output_pdf", "reports/report.pdf"))

    summary = build_findings()
    manual_queue = read_json("outputs/manual_validation_queue.json", default=[]) or []
    all_findings = summary.get("all_findings", []) if isinstance(summary, dict) else []
    owasp_web = sorted({finding.get("owasp_web") for finding in all_findings if finding.get("owasp_web")})
    owasp_api = sorted({finding.get("owasp_api") for finding in all_findings if finding.get("owasp_api")})
    dynamic_scope = summary.get("dynamic_scope", {}) if isinstance(summary.get("dynamic_scope"), dict) else {}
    endpoints_raw = read_json("outputs/endpoints.json", default=[]) or []
    endpoints = [{"url": url, "hostname": urlparse(str(url)).hostname or ""} for url in endpoints_raw]
    potential_findings = summary.get("potential_findings", [])
    for finding in potential_findings:
        finding["hostname"] = urlparse(str(finding.get("url", ""))).hostname or ""

    env = Environment(
        loader=FileSystemLoader("agent/report"),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("template.html")
    html = template.render(
        project_name=assessment_config.get("project_name") or report_config.get("project_name", "AI Security Analyst Platform"),
        assessment=assessment_config,
        target=target,
        root_domain=dynamic_scope.get("root_domain", ""),
        scope=dynamic_scope.get("allowed_hosts", []),
        dynamic_scope=dynamic_scope,
        discovered_subdomains=summary.get("discovered_subdomains", []),
        live_hosts=summary.get("live_hosts", []),
        external_dependencies=summary.get("external_dependencies", []),
        endpoints=endpoints,
        total_endpoints=summary.get("total_endpoints", 0),
        total_findings=summary.get("total_findings", 0),
        security_header_findings=summary.get("security_header_findings", []),
        technology_fingerprint=summary.get("technology_fingerprint", {}),
        auth_endpoints=summary.get("auth_endpoints", []),
        auth_crawl=read_json("outputs/authenticated_crawl_summary.json", default={}) or {},
        auth_crawl_urls=read_json("outputs/authenticated_crawl_urls.json", default=[]) or [],
        forms_discovered=read_json("outputs/forms_discovered.json", default=[]) or [],
        http_history=read_json("outputs/http_history.json", default=[]) or [],
        potential_findings=potential_findings,
        manual_validation_queue=manual_queue,
        owasp_web=owasp_web,
        owasp_api=owasp_api,
    )
    Path(output_html).parent.mkdir(parents=True, exist_ok=True)
    Path(output_html).write_text(html, encoding="utf-8")

    pdf_status = "not_generated"
    try:
        from weasyprint import HTML

        HTML(string=html, base_url=str(Path.cwd())).write_pdf(output_pdf)
        pdf_status = output_pdf
    except Exception:
        pdf_status = "weasyprint_unavailable_or_failed"

    dashboard = generate_dashboard(config, target, str(assessment_config.get("type") or assessment_config.get("profile") or "Black Box"), "reports/assessment.html")
    return {"html": str(dashboard.get("html", output_html)), "legacy_html": output_html, "pdf": pdf_status}
