from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
import re
from typing import Any

from core.logging import redact_sensitive_data


VALID_CATEGORIES = {
    "security_headers",
    "authentication",
    "authorization",
    "session_management",
    "input_validation",
    "api_security",
    "information_disclosure",
    "configuration",
    "transport_security",
    "dns_security",
    "business_logic",
    "rate_limiting",
    "file_upload",
    "unknown",
}
VALID_PRIORITIES = {"info", "low", "medium", "high", "critical"}
VALID_VALIDATION_STATUSES = {"needs_manual_validation", "validated", "not_applicable", "false_positive"}
PRIORITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_SAFETY_NOTE = "Do not perform exploitation, brute force, denial-of-service, credential theft, or authentication bypass."
SAFE_GENERIC_STEP = "Perform only authorized, non-destructive manual validation for this area."

UNSAFE_PATTERNS = (
    r"\bexploit\b",
    r"\breverse shell\b",
    r"\bpayload\b",
    r"\bdropper\b",
    r"\bmalware\b",
    r"\bransomware\b",
    r"\bbrute force\b",
    r"\bcredential theft\b",
    r"\bcredential stuffing\b",
    r"\bsteal cookie\b",
    r"\bsteal token\b",
    r"\bdump database\b",
    r"\bbypass authentication\b",
    r"\bddos\b",
    r"\bdos\b",
    r"\bfuzz aggressively\b",
    r"\bsqlmap --risk\b",
    r"\bsqlmap --level\b",
)


@dataclass(frozen=True)
class ManualTestRecommendation:
    recommendation_id: str
    area: str
    category: str
    priority: str
    title: str
    description: str
    manual_steps: list[str]
    evidence_refs: list[str] = field(default_factory=list)
    related_finding_fingerprints: list[str] = field(default_factory=list)
    validation_status: str = "needs_manual_validation"
    safety_notes: list[str] = field(default_factory=list)


def normalize_category(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in VALID_CATEGORIES else "unknown"


def normalize_priority(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in VALID_PRIORITIES else "info"


def normalize_validation_status(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in VALID_VALIDATION_STATUSES else "needs_manual_validation"


def contains_unsafe_testing_instruction(text: str) -> bool:
    value = str(text or "").strip().lower()
    return any(re.search(pattern, value) for pattern in UNSAFE_PATTERNS)


def _unique_clean(values: list[str] | None) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values or []:
        safe = str(redact_sensitive_data(value or "")).strip()
        if safe and safe not in seen:
            seen.add(safe)
            result.append(safe)
    return result


def sanitize_manual_steps(steps: list[str]) -> list[str]:
    sanitized: list[str] = []
    for step in list(steps or []):
        safe_step = str(redact_sensitive_data(step or "")).strip()
        if not safe_step:
            continue
        if contains_unsafe_testing_instruction(safe_step):
            safe_step = SAFE_GENERIC_STEP
        sanitized.append(safe_step)
    result = _unique_clean(sanitized)
    return result or ["Review available evidence and document manual validation steps safely."]


def create_recommendation_id(
    area: str,
    category: str,
    title: str,
    evidence_refs: list[str] | None = None,
    related_finding_fingerprints: list[str] | None = None,
) -> str:
    payload = {
        "area": str(redact_sensitive_data(area or "")).strip().lower(),
        "category": normalize_category(category),
        "title": str(redact_sensitive_data(title or "")).strip().lower(),
        "evidence_refs": sorted(_unique_clean(evidence_refs)),
        "related_finding_fingerprints": sorted(_unique_clean(related_finding_fingerprints)),
    }
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return f"mt_{sha256(serialized.encode('utf-8')).hexdigest()[:16]}"


def _require_text(value: str, field_name: str) -> str:
    safe = str(redact_sensitive_data(value or "")).strip()
    if not safe:
        raise ValueError(f"Manual testing recommendation {field_name} must be non-empty.")
    return safe


def create_manual_test_recommendation(
    area: str,
    category: str,
    priority: str,
    title: str,
    description: str,
    manual_steps: list[str],
    evidence_refs: list[str] | None = None,
    related_finding_fingerprints: list[str] | None = None,
    safety_notes: list[str] | None = None,
) -> ManualTestRecommendation:
    safe_area = _require_text(area, "area")
    safe_title = _require_text(title, "title")
    safe_description = _require_text(description, "description")
    safe_category = normalize_category(category)
    safe_priority = normalize_priority(priority)
    safe_evidence_refs = _unique_clean(evidence_refs)
    safe_fingerprints = _unique_clean(related_finding_fingerprints)
    safe_steps = sanitize_manual_steps(manual_steps)
    notes = _unique_clean([DEFAULT_SAFETY_NOTE] + list(safety_notes or []))
    notes = [SAFE_GENERIC_STEP if contains_unsafe_testing_instruction(note) and note != DEFAULT_SAFETY_NOTE else note for note in notes]
    return ManualTestRecommendation(
        recommendation_id=create_recommendation_id(
            safe_area,
            safe_category,
            safe_title,
            evidence_refs=safe_evidence_refs,
            related_finding_fingerprints=safe_fingerprints,
        ),
        area=safe_area,
        category=safe_category,
        priority=safe_priority,
        title=safe_title,
        description=safe_description,
        manual_steps=safe_steps,
        evidence_refs=safe_evidence_refs,
        related_finding_fingerprints=safe_fingerprints,
        validation_status="needs_manual_validation",
        safety_notes=notes,
    )


def manual_test_recommendation_to_dict(item: ManualTestRecommendation) -> dict[str, Any]:
    return redact_sensitive_data(asdict(item))


def manual_test_recommendation_from_dict(data: dict[str, Any]) -> ManualTestRecommendation:
    payload = data if isinstance(data, dict) else {}
    return ManualTestRecommendation(
        recommendation_id=str(redact_sensitive_data(payload.get("recommendation_id") or "")),
        area=_require_text(str(payload.get("area") or ""), "area"),
        category=normalize_category(str(payload.get("category") or "")),
        priority=normalize_priority(str(payload.get("priority") or "")),
        title=_require_text(str(payload.get("title") or ""), "title"),
        description=_require_text(str(payload.get("description") or ""), "description"),
        manual_steps=sanitize_manual_steps(list(payload.get("manual_steps") or [])),
        evidence_refs=_unique_clean(list(payload.get("evidence_refs") or [])),
        related_finding_fingerprints=_unique_clean(list(payload.get("related_finding_fingerprints") or [])),
        validation_status=normalize_validation_status(str(payload.get("validation_status") or "")),
        safety_notes=_unique_clean(list(payload.get("safety_notes") or []) or [DEFAULT_SAFETY_NOTE]),
    )


def infer_category_from_finding(finding: dict[str, Any]) -> str:
    payload = finding if isinstance(finding, dict) else {}
    module = str(payload.get("module") or "").lower()
    finding_type = str(payload.get("finding_type") or "").lower()
    title = str(payload.get("title") or "").lower()
    combined = f"{module} {finding_type} {title}"
    if module == "security_headers" or any(term in combined for term in ("header", "csp", "hsts", "x-frame")):
        return "security_headers"
    if "dns" in finding_type or module == "passive_dns":
        return "dns_security"
    if any(term in combined for term in ("authorization", "idor", "access control", "object level")):
        return "authorization"
    if any(term in combined for term in ("session", "token", "cookie")):
        return "session_management"
    if any(term in combined for term in ("auth", "login")):
        return "authentication"
    if any(term in combined for term in ("api", "openapi", "swagger", "graphql")):
        return "api_security"
    if any(term in combined for term in ("information disclosure", "server", "banner", "debug")):
        return "information_disclosure"
    if any(term in combined for term in ("tls", "https")):
        return "transport_security"
    if any(term in combined for term in ("rate limit", "throttle")):
        return "rate_limiting"
    if any(term in combined for term in ("upload", "file")):
        return "file_upload"
    return "unknown"


def infer_priority_from_finding(finding: dict[str, Any]) -> str:
    severity = normalize_priority(str((finding or {}).get("severity") or "info"))
    confidence = str((finding or {}).get("confidence") or "low").strip().lower()
    if severity in {"critical", "high"} and confidence == "high":
        return "high"
    if severity == "high" and confidence == "medium":
        return "medium"
    if severity == "medium" and confidence in {"high", "medium"}:
        return "medium"
    if severity == "low":
        return "low"
    if severity == "info":
        return "info"
    return "low"


def build_safe_manual_steps_for_category(category: str, finding: dict[str, Any]) -> list[str]:
    safe_category = normalize_category(category)
    templates = {
        "security_headers": [
            "Review the affected response and confirm whether the header is consistently missing.",
            "Evaluate whether the missing header increases risk based on actual application behavior.",
            "Confirm recommended header configuration with the application team.",
            "Document affected assets, evidence, and remediation guidance.",
        ],
        "authorization": [
            "Review role and permission boundaries for the affected endpoint.",
            "Verify that access control decisions are enforced server-side.",
            "Compare expected access behavior using authorized test accounts only.",
            "Document any inconsistent authorization behavior with evidence.",
        ],
        "authentication": [
            "Review authentication flow and expected security controls.",
            "Confirm that login, password reset, and session lifecycle controls match policy.",
            "Use only authorized test accounts and non-destructive validation.",
            "Document observed gaps and remediation guidance.",
        ],
        "session_management": [
            "Review session lifecycle, timeout, renewal, and logout behavior with authorized test accounts.",
            "Confirm session-related controls align with application policy.",
            "Document any observed gaps without collecting or exposing sensitive session values.",
        ],
        "api_security": [
            "Review API endpoints, methods, parameters, and expected authorization requirements.",
            "Check whether responses expose more data than expected.",
            "Validate schema and error handling using safe, authorized requests only.",
            "Document affected endpoints and evidence.",
        ],
        "dns_security": [
            "Review DNS records for missing or weak email/domain security controls.",
            "Confirm SPF, DMARC, and CAA configuration with domain owner.",
            "Validate that DNS observations are current and authorized.",
            "Document records and recommended changes.",
        ],
        "information_disclosure": [
            "Review the evidence to confirm whether exposed information is sensitive in context.",
            "Confirm expected error handling and banner exposure with the application team.",
            "Document exposed fields, affected assets, and remediation guidance.",
        ],
        "transport_security": [
            "Review HTTPS and TLS-related observations against the approved security baseline.",
            "Confirm whether transport security controls are consistently configured.",
            "Document affected assets and recommended configuration changes.",
        ],
        "rate_limiting": [
            "Review expected rate limiting and throttling controls with the application team.",
            "Validate behavior only with low-volume, authorized manual checks.",
            "Document endpoints where controls require further review.",
        ],
        "file_upload": [
            "Review allowed file types, size limits, storage handling, and approval workflows.",
            "Validate upload controls only with benign authorized test files.",
            "Document any control gaps and remediation guidance.",
        ],
        "business_logic": [
            "Review the affected workflow and expected business rules with product owners.",
            "Validate behavior using authorized test accounts and non-destructive scenarios.",
            "Document discrepancies between expected and observed behavior.",
        ],
    }
    return sanitize_manual_steps(templates.get(safe_category, ["Review available evidence and identify safe manual validation tasks for this finding."]))


def _finding_evidence_refs(finding: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    if finding.get("evidence_id"):
        refs.append(str(finding["evidence_id"]))
    refs.extend(str(item) for item in finding.get("related_evidence_ids") or [])
    return _unique_clean(refs)


def recommendation_from_finding(finding: dict[str, Any]) -> ManualTestRecommendation:
    payload = finding if isinstance(finding, dict) else {}
    title = str(redact_sensitive_data(payload.get("title") or "Potential finding")).strip()
    category = infer_category_from_finding(payload)
    priority = infer_priority_from_finding(payload)
    evidence_text = str(redact_sensitive_data(payload.get("evidence") or "available evidence")).strip()
    description = (
        f"This potential finding requires manual validation based on the recorded evidence: {evidence_text}. "
        "Treat the issue as unconfirmed until a human pentester validates it."
    )
    return create_manual_test_recommendation(
        area=_area_for_category(category, title),
        category=category,
        priority=priority,
        title=f"Manual validation for: {title}",
        description=description,
        manual_steps=build_safe_manual_steps_for_category(category, payload),
        evidence_refs=_finding_evidence_refs(payload),
        related_finding_fingerprints=[str(payload["fingerprint"])] if payload.get("fingerprint") else [],
    )


def _area_for_category(category: str, fallback_title: str) -> str:
    labels = {
        "security_headers": "Security Headers",
        "authentication": "Authentication",
        "authorization": "Authorization",
        "session_management": "Session Management",
        "api_security": "API Security",
        "information_disclosure": "Information Disclosure",
        "transport_security": "Transport Security",
        "dns_security": "DNS Security",
        "rate_limiting": "Rate Limiting",
        "file_upload": "File Upload",
        "business_logic": "Business Logic",
    }
    return labels.get(normalize_category(category), fallback_title or "General Assessment")


def generate_manual_testing_recommendations(
    findings: list[dict[str, Any]] | None = None,
    evidence_items: list[Any] | None = None,
) -> list[ManualTestRecommendation]:
    recommendations: dict[str, ManualTestRecommendation] = {}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        recommendation = recommendation_from_finding(_attach_evidence_refs(finding, evidence_items))
        recommendations[recommendation.recommendation_id] = recommendation
    if not recommendations:
        generic = create_manual_test_recommendation(
            area="General Assessment",
            category="unknown",
            priority="info",
            title="General manual review",
            description="Review available assessment context and evidence before selecting manual validation tasks.",
            manual_steps=[
                "Review application scope and confirm authorization.",
                "Review available evidence and identify areas requiring manual validation.",
                "Document any confirmed issues with evidence and remediation guidance.",
            ],
        )
        recommendations[generic.recommendation_id] = generic
    return sorted(
        recommendations.values(),
        key=lambda item: (-PRIORITY_RANK.get(item.priority, 0), item.category, item.title.lower()),
    )


def _attach_evidence_refs(finding: dict[str, Any], evidence_items: list[Any] | None) -> dict[str, Any]:
    payload = dict(finding)
    refs = _finding_evidence_refs(payload)
    for item in evidence_items or []:
        evidence_id = getattr(item, "evidence_id", None)
        title = getattr(item, "title", "")
        if evidence_id and title and str(title).strip().lower() == str(payload.get("title") or "").strip().lower():
            refs.append(str(evidence_id))
    if refs:
        payload["related_evidence_ids"] = _unique_clean(refs)
    return payload


def summarize_manual_testing_recommendations(
    recommendations: list[ManualTestRecommendation],
) -> dict[str, Any]:
    by_priority = {priority: 0 for priority in VALID_PRIORITIES}
    by_category: dict[str, int] = {}
    needs_manual_validation = 0
    for item in recommendations or []:
        by_priority[item.priority] = by_priority.get(item.priority, 0) + 1
        by_category[item.category] = by_category.get(item.category, 0) + 1
        if item.validation_status == "needs_manual_validation":
            needs_manual_validation += 1
    return {
        "total": len(recommendations or []),
        "by_priority": by_priority,
        "by_category": by_category,
        "needs_manual_validation": needs_manual_validation,
    }
