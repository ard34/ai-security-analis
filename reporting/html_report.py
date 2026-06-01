from __future__ import annotations

import html

from core.models import ScanResult
from core.policies import redact_value


def render_html_report(result: ScanResult) -> str:
    findings = "\n".join(
        f"<li><strong>{html.escape(finding.severity)}</strong>: {html.escape(finding.title)} "
        f"<em>potential={finding.is_potential}</em></li>"
        for finding in result.findings
    )
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
<h2>Potential Findings</h2><ul>{findings}</ul>
<h2>Evidence</h2><ul>{evidence}</ul>
<h2>Manual Recommendations</h2><ul>{recommendations}</ul>
</body>
</html>"""

