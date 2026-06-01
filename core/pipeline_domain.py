from __future__ import annotations

from urllib.parse import urlunparse

from core.assessment import Assessment
from core.execution import ExecutionEngine
from core.finding_dedup import deduplicate_findings
from core.logging import AuditLogger
from core.manual_testing import recommendations_for_findings
from core.models import Asset, Evidence, Finding, ScanResult
from core.policies import DomainRunPolicy
from modules.headers import analyze_security_headers
from modules.http_fingerprint import fingerprint_http
from modules.live_dns import resolve_a_aaaa
from modules.live_headers import fetch_security_headers
from modules.robots_sitemap import fetch_robots_and_sitemap


def run_domain_assessment(target: str, assessment: Assessment, policy: DomainRunPolicy) -> ScanResult:
    host = assessment.scope().require_in_scope(target)
    audit = AuditLogger(policy.audit_log_path or "logs/audit.jsonl")
    engine = ExecutionEngine(policy=policy, assessment_approved=assessment.approved, audit=audit)
    audit.event("domain_assessment_started", target=host, assessment=assessment.name)
    result = ScanResult(target=host, workflow="type2_domain")
    asset = Asset(type="domain", value=host)
    result.assets.append(asset)
    scheme_url = urlunparse(("https", host, "", "", "", ""))
    dns = resolve_a_aaaa(host, engine)
    result.evidence.append(Evidence(source="dns_a_aaaa", content=str(dns)))
    headers = fetch_security_headers(scheme_url, engine)
    result.evidence.append(Evidence(source="security_headers", content=str(headers)))
    for missing in analyze_security_headers(headers.get("headers", {})):
        result.findings.append(
            Finding(
                title=f"Potential missing security header: {missing}",
                severity="low",
                description="A safe HEAD request did not observe this defensive response header.",
                asset_id=asset.id,
            )
        )
    fingerprint = fingerprint_http(scheme_url, engine)
    result.evidence.append(Evidence(source="http_fingerprint", content=str(fingerprint)))
    robots = fetch_robots_and_sitemap(scheme_url, engine)
    result.evidence.append(Evidence(source="robots_sitemap", content=str(robots)))
    result.findings = deduplicate_findings(result.findings)
    result.recommendations = recommendations_for_findings(result.findings)
    result.audit_events.append(audit.event("domain_assessment_completed", target=host))
    return result.complete()

