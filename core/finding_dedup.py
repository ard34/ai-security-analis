from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any
import re

from core.logging import redact_sensitive_data


VALID_SEVERITIES = ("info", "low", "medium", "high", "critical")
VALID_CONFIDENCES = ("low", "medium", "high")
VALID_VALIDATION_STATUSES = {"needs_manual_validation", "confirmed", "false_positive", "accepted_risk", "fixed"}
SEVERITY_RANK = {value: index for index, value in enumerate(VALID_SEVERITIES)}
CONFIDENCE_RANK = {value: index for index, value in enumerate(VALID_CONFIDENCES)}


@dataclass
class DedupedFinding:
    fingerprint: str
    title: str
    severity: str
    confidence: str
    target: str
    asset: str | None
    endpoint: str | None
    module: str
    finding_type: str
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    occurrences: int = 1
    is_potential: bool = True
    validation_status: str = "needs_manual_validation"
    related_evidence_ids: list[str] = field(default_factory=list)


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(redact_sensitive_data(value)).strip().lower())


def normalize_severity(value: str | None) -> str:
    normalized = normalize_text(value)
    return normalized if normalized in VALID_SEVERITIES else "info"


def normalize_confidence(value: str | None) -> str:
    normalized = normalize_text(value)
    return normalized if normalized in VALID_CONFIDENCES else "low"


def create_finding_fingerprint(finding: dict[str, Any]) -> str:
    payload = {
        "target": normalize_text(finding.get("target")),
        "asset": normalize_text(finding.get("asset")),
        "endpoint": normalize_text(finding.get("endpoint")),
        "module": normalize_text(finding.get("module")),
        "finding_type": normalize_text(finding.get("finding_type")),
        "title": normalize_text(finding.get("title")),
    }
    serialized = "|".join(payload[key] for key in sorted(payload))
    return f"fd_{sha256(serialized.encode('utf-8')).hexdigest()[:16]}"


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        safe = str(redact_sensitive_data(value or "")).strip()
        if safe and safe not in seen:
            seen.add(safe)
            result.append(safe)
    return result


def finding_to_deduped_finding(
    finding: dict[str, Any],
    related_evidence_ids: list[str] | None = None,
) -> DedupedFinding:
    payload = dict(finding or {})
    if payload.get("is_potential", True) is not True:
        raise ValueError("Finding must be potential before deduplication.")
    severity = normalize_severity(payload.get("severity"))
    confidence = normalize_confidence(payload.get("confidence"))
    return DedupedFinding(
        fingerprint=create_finding_fingerprint(payload),
        title=str(redact_sensitive_data(payload.get("title") or "")).strip(),
        severity=severity,
        confidence=confidence,
        target=str(redact_sensitive_data(payload.get("target") or "")).strip(),
        asset=redact_sensitive_data(payload.get("asset")) if payload.get("asset") else None,
        endpoint=redact_sensitive_data(payload.get("endpoint")) if payload.get("endpoint") else None,
        module=str(redact_sensitive_data(payload.get("module") or "")).strip(),
        finding_type=str(redact_sensitive_data(payload.get("finding_type") or "")).strip(),
        evidence=_unique([str(payload.get("evidence") or "")]),
        recommendations=_unique([str(payload.get("recommendation") or "")]),
        sources=_unique([str(payload.get("source") or "")]),
        occurrences=1,
        is_potential=True,
        validation_status="needs_manual_validation",
        related_evidence_ids=_unique(related_evidence_ids or []),
    )


def _max_ranked(left: str, right: str, ranks: dict[str, int]) -> str:
    return left if ranks.get(left, 0) >= ranks.get(right, 0) else right


def merge_deduped_findings(
    existing: DedupedFinding,
    incoming: DedupedFinding,
) -> DedupedFinding:
    if existing.fingerprint != incoming.fingerprint:
        raise ValueError("Cannot merge findings with different fingerprints.")
    return DedupedFinding(
        fingerprint=existing.fingerprint,
        title=existing.title or incoming.title,
        severity=_max_ranked(existing.severity, incoming.severity, SEVERITY_RANK),
        confidence=_max_ranked(existing.confidence, incoming.confidence, CONFIDENCE_RANK),
        target=existing.target or incoming.target,
        asset=existing.asset or incoming.asset,
        endpoint=existing.endpoint or incoming.endpoint,
        module=existing.module or incoming.module,
        finding_type=existing.finding_type or incoming.finding_type,
        evidence=_unique(existing.evidence + incoming.evidence),
        recommendations=_unique(existing.recommendations + incoming.recommendations),
        sources=_unique(existing.sources + incoming.sources),
        occurrences=existing.occurrences + incoming.occurrences,
        is_potential=True,
        validation_status=existing.validation_status or incoming.validation_status or "needs_manual_validation",
        related_evidence_ids=_unique(existing.related_evidence_ids + incoming.related_evidence_ids),
    )


def _evidence_id_map(evidence_items: list[Any] | None) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for item in evidence_items or []:
        data = getattr(item, "data", None)
        evidence_id = getattr(item, "evidence_id", None)
        if not isinstance(data, dict) or not evidence_id:
            continue
        finding = {
            "target": getattr(item, "target", ""),
            "asset": getattr(item, "asset", ""),
            "endpoint": getattr(item, "endpoint", ""),
            "module": data.get("module", ""),
            "finding_type": data.get("finding_type", ""),
            "title": getattr(item, "title", ""),
        }
        fingerprint = create_finding_fingerprint(finding)
        mapping.setdefault(fingerprint, []).append(str(evidence_id))
    return mapping


def deduplicate_findings(
    findings: list[dict[str, Any]],
    evidence_items: list[Any] | None = None,
) -> list[DedupedFinding]:
    evidence_map = _evidence_id_map(evidence_items)
    merged: dict[str, DedupedFinding] = {}
    for finding in findings or []:
        payload = dict(finding)
        fingerprint = create_finding_fingerprint(payload)
        incoming = finding_to_deduped_finding(payload, related_evidence_ids=evidence_map.get(fingerprint, []))
        if incoming.fingerprint in merged:
            merged[incoming.fingerprint] = merge_deduped_findings(merged[incoming.fingerprint], incoming)
        else:
            merged[incoming.fingerprint] = incoming
    return sorted(
        merged.values(),
        key=lambda item: (-SEVERITY_RANK.get(item.severity, 0), item.title.lower(), str(item.asset or ""), str(item.endpoint or "")),
    )


def deduped_finding_to_dict(item: DedupedFinding) -> dict[str, Any]:
    payload = asdict(item)
    payload["is_potential"] = True
    if payload.get("validation_status") not in VALID_VALIDATION_STATUSES:
        payload["validation_status"] = "needs_manual_validation"
    return redact_sensitive_data(payload)


def deduped_findings_to_dicts(items: list[DedupedFinding]) -> list[dict[str, Any]]:
    return [deduped_finding_to_dict(item) for item in items or []]


def summarize_deduped_findings(items: list[DedupedFinding]) -> dict[str, Any]:
    by_severity = {value: 0 for value in VALID_SEVERITIES}
    by_confidence = {value: 0 for value in VALID_CONFIDENCES}
    by_validation_status: dict[str, int] = {}
    total_occurrences = 0
    for item in items or []:
        by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
        by_confidence[item.confidence] = by_confidence.get(item.confidence, 0) + 1
        by_validation_status[item.validation_status] = by_validation_status.get(item.validation_status, 0) + 1
        total_occurrences += item.occurrences
    return {
        "total_unique": len(items or []),
        "total_occurrences": total_occurrences,
        "by_severity": by_severity,
        "by_confidence": by_confidence,
        "by_validation_status": by_validation_status,
    }
