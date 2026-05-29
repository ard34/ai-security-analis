from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class Finding:
    title: str
    type: str
    severity: str
    confidence: str
    url: str
    evidence: str
    recommendation: str
    owasp_web: str
    owasp_api: str
    manual_validation_required: bool = True
    status: str = "Potential"
    testing_methodology: str = "black_box"
    evidence_source: str = "HTTP response"
    black_box_limitations: str = "Finding is based on external request/response behavior. Source code and server-side authorization logic were not reviewed."
    safe_testing_note: str = "Manual validation only. Do not brute force, exploit, perform denial of service, upload shells, or exfiltrate data."

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
