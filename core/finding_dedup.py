from __future__ import annotations

import hashlib

from core.models import Finding
from core.risk import normalize_severity


def finding_fingerprint(finding: Finding) -> str:
    stable = "|".join(
        [
            finding.title.strip().lower(),
            normalize_severity(finding.severity),
            str(finding.asset_id or ""),
            str(finding.endpoint_id or ""),
        ]
    )
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    deduped: list[Finding] = []
    for finding in findings:
        fingerprint = finding_fingerprint(finding)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        finding.metadata["fingerprint"] = fingerprint
        deduped.append(finding)
    return deduped

