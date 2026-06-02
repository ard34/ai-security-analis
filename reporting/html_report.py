from __future__ import annotations

import html

from core.models import Finding, ScanResult
from core.policies import redact_value

VALIDATION_READY_DISCLAIMER = (
    "Validation-ready findings are logic-derived from source code and require manual confirmation "
    "by an authorized pentester."
)


def _list(items: list[object]) -> str:
    return "<ul>" + "".join(f"<li>{html.escape(str(item))}</li>" for item in items) + "</ul>"


def _finding_detail(finding: Finding) -> str:
    locations = [
        f"{location.get('file', '')}:{location.get('line', '')}" for location in finding.source_locations
    ]
    validation = ""
    if finding.validation_status in {"logic_analyzed", "validation_ready"}:
        validation = f"""
<div>
<p><strong>Validation status:</strong> {html.escape(finding.validation_status)}</p>
<p><strong>Confidence score:</strong> {html.escape(str(finding.confidence_score))}</p>
<p><strong>Source location:</strong> {html.escape(", ".join(locations))}</p>
<p><strong>Affected route/function:</strong>
{html.escape(", ".join([*finding.affected_routes, *finding.affected_functions]))}</p>
<p><strong>Vulnerable flow:</strong> {html.escape(finding.vulnerable_flow)}</p>
<p><strong>Root cause:</strong> {html.escape(finding.root_cause)}</p>
<p><strong>Missing control:</strong> {html.escape(finding.missing_control)}</p>
<p><strong>Exploitability reasoning:</strong> {html.escape(finding.exploitability_reasoning)}</p>
<p><strong>Manual validation steps:</strong></p>{_list(finding.manual_validation_steps)}
<p><strong>Expected evidence:</strong></p>{_list(finding.expected_evidence)}
<p><strong>False positive checks:</strong></p>{_list(finding.false_positive_checks)}
<p><strong>Remediation:</strong> {html.escape(finding.remediation_guidance)}</p>
</div>"""
    return (
        f"<li><strong>{html.escape(finding.severity)}</strong>: {html.escape(finding.title)} "
        f"<em>potential={finding.is_potential}</em>{validation}</li>"
    )


def render_html_report(result: ScanResult) -> str:
    findings = "\n".join(_finding_detail(finding) for finding in result.findings)
    evidence = "\n".join(
        f"<li>{html.escape(item.source)}: <pre>{html.escape(str(redact_value('content', item.content)))}</pre></li>"
        for item in result.evidence
    )
    recommendations = "\n".join(f"<li>{html.escape(item)}</li>" for item in result.recommendations)
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>AI Security Analyst Report</title></head>
<body>
<h1>AI Security Analyst Report</h1>
<p>Workflow: {html.escape(result.workflow)}</p>
<p>Target: {html.escape(result.target)}</p>
<p>{html.escape(VALIDATION_READY_DISCLAIMER)}</p>
<h2>Potential Findings</h2><ul>{findings}</ul>
<h2>Evidence</h2><ul>{evidence}</ul>
<h2>Manual Recommendations</h2><ul>{recommendations}</ul>
</body>
</html>"""

