from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any

from core.logging import redact_sensitive_data


VALID_EVIDENCE_TYPES = {
    "http_header",
    "dns_record",
    "endpoint",
    "technology",
    "waf_detection",
    "finding_evidence",
    "audit_event",
    "manual_note",
    "imported_artifact",
}


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    scan_id: str | None
    target: str
    asset: str | None
    endpoint: str | None
    source: str
    evidence_type: str
    title: str
    data: dict[str, Any]
    created_at: str
    tags: list[str] = field(default_factory=list)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sanitize_evidence_data(data: dict[str, Any]) -> dict[str, Any]:
    payload = data if isinstance(data, dict) else {}
    sanitized = redact_sensitive_data(payload)
    return dict(sanitized) if isinstance(sanitized, dict) else {}


def _validate_evidence_type(evidence_type: str) -> str:
    normalized = str(evidence_type or "").strip().lower()
    if normalized not in VALID_EVIDENCE_TYPES:
        raise ValueError(f"Invalid evidence type: {evidence_type}")
    return normalized


def _require_non_empty(value: str, field_name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ValueError(f"Evidence {field_name} must be non-empty.")
    return normalized


def create_evidence_id(
    target: str,
    source: str,
    evidence_type: str,
    title: str,
    data: dict[str, Any],
) -> str:
    payload = {
        "target": str(redact_sensitive_data(target or "")).strip().lower(),
        "source": str(redact_sensitive_data(source or "")).strip().lower(),
        "evidence_type": _validate_evidence_type(evidence_type),
        "title": str(redact_sensitive_data(title or "")).strip().lower(),
        "data": sanitize_evidence_data(data),
    }
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return f"ev_{sha256(serialized.encode('utf-8')).hexdigest()[:16]}"


def create_evidence_item(
    target: str,
    source: str,
    evidence_type: str,
    title: str,
    data: dict[str, Any],
    scan_id: str | None = None,
    asset: str | None = None,
    endpoint: str | None = None,
    tags: list[str] | None = None,
) -> EvidenceItem:
    safe_target = _require_non_empty(str(redact_sensitive_data(target or "")), "target")
    safe_source = _require_non_empty(str(redact_sensitive_data(source or "")), "source")
    safe_title = _require_non_empty(str(redact_sensitive_data(title or "")), "title")
    safe_type = _validate_evidence_type(evidence_type)
    safe_data = sanitize_evidence_data(data)
    return EvidenceItem(
        evidence_id=create_evidence_id(safe_target, safe_source, safe_type, safe_title, safe_data),
        scan_id=redact_sensitive_data(scan_id),
        target=safe_target,
        asset=redact_sensitive_data(asset),
        endpoint=redact_sensitive_data(endpoint),
        source=safe_source,
        evidence_type=safe_type,
        title=safe_title,
        data=safe_data,
        created_at=utc_now_iso(),
        tags=[str(redact_sensitive_data(tag)).strip() for tag in tags or [] if str(tag).strip()],
    )


def evidence_item_to_dict(item: EvidenceItem) -> dict[str, Any]:
    return sanitize_evidence_data(asdict(item))


def evidence_item_from_dict(data: dict[str, Any]) -> EvidenceItem:
    payload = sanitize_evidence_data(data)
    item = EvidenceItem(
        evidence_id=str(payload.get("evidence_id") or ""),
        scan_id=payload.get("scan_id"),
        target=str(payload.get("target") or ""),
        asset=payload.get("asset"),
        endpoint=payload.get("endpoint"),
        source=str(payload.get("source") or ""),
        evidence_type=_validate_evidence_type(str(payload.get("evidence_type") or "")),
        title=str(payload.get("title") or ""),
        data=sanitize_evidence_data(payload.get("data") if isinstance(payload.get("data"), dict) else {}),
        created_at=str(payload.get("created_at") or ""),
        tags=list(payload.get("tags") or []),
    )
    _require_non_empty(item.evidence_id, "evidence_id")
    _require_non_empty(item.target, "target")
    _require_non_empty(item.source, "source")
    _require_non_empty(item.title, "title")
    return item


def _finding_value(finding: dict[str, Any], key: str) -> Any:
    return finding.get(key, "")


def evidence_from_finding(finding: dict[str, Any], scan_id: str | None = None) -> EvidenceItem:
    payload = finding if isinstance(finding, dict) else {}
    title = str(_finding_value(payload, "title") or "Finding evidence")
    source = str(_finding_value(payload, "source") or _finding_value(payload, "module") or "finding")
    data = {
        "finding_type": _finding_value(payload, "finding_type"),
        "severity": _finding_value(payload, "severity"),
        "confidence": _finding_value(payload, "confidence"),
        "evidence": _finding_value(payload, "evidence"),
        "recommendation": _finding_value(payload, "recommendation"),
        "module": _finding_value(payload, "module"),
        "is_potential": payload.get("is_potential", True),
    }
    return create_evidence_item(
        target=str(_finding_value(payload, "target") or ""),
        source=source,
        evidence_type="finding_evidence",
        title=title,
        data=data,
        scan_id=scan_id,
        asset=_finding_value(payload, "asset") or None,
        endpoint=_finding_value(payload, "endpoint") or None,
        tags=["finding", str(_finding_value(payload, "module") or "module")],
    )


def collect_evidence_from_scan_result(scan_result: dict[str, Any]) -> list[EvidenceItem]:
    result = scan_result if isinstance(scan_result, dict) else {}
    scan_id = result.get("scan_id")
    target = str(result.get("normalized_target") or result.get("target") or "unknown")
    items: list[EvidenceItem] = []

    for finding in result.get("findings") or []:
        if isinstance(finding, dict):
            finding_payload = dict(finding)
        elif hasattr(finding, "to_dict"):
            finding_payload = finding.to_dict()
        elif hasattr(finding, "__dict__"):
            finding_payload = dict(finding.__dict__)
        else:
            continue
        finding_payload.setdefault("target", target)
        items.append(evidence_from_finding(finding_payload, scan_id=scan_id))

    for event in result.get("audit_events") or []:
        if isinstance(event, dict):
            items.append(
                create_evidence_item(
                    target=target,
                    source=str(event.get("source") or "audit"),
                    evidence_type="audit_event",
                    title=str(event.get("event_type") or "audit_event"),
                    data=event,
                    scan_id=scan_id,
                    tags=["audit"],
                )
            )

    for asset in result.get("assets") or []:
        asset_value = asset.get("url") if isinstance(asset, dict) else asset
        if asset_value:
            items.append(
                create_evidence_item(
                    target=target,
                    source="scan_result",
                    evidence_type="endpoint",
                    title="Asset observed",
                    data={"asset": asset},
                    scan_id=scan_id,
                    asset=str(asset_value),
                    tags=["asset"],
                )
            )

    for endpoint in result.get("endpoints") or []:
        endpoint_value = endpoint.get("path") or endpoint.get("url") if isinstance(endpoint, dict) else endpoint
        if endpoint_value:
            items.append(
                create_evidence_item(
                    target=target,
                    source="scan_result",
                    evidence_type="endpoint",
                    title="Endpoint observed",
                    data={"endpoint": endpoint},
                    scan_id=scan_id,
                    endpoint=str(endpoint_value),
                    tags=["endpoint"],
                )
            )

    return items


def filter_evidence(
    items: list[EvidenceItem],
    target: str | None = None,
    source: str | None = None,
    evidence_type: str | None = None,
    tag: str | None = None,
) -> list[EvidenceItem]:
    filtered: list[EvidenceItem] = []
    for item in items or []:
        if target is not None and item.target != target:
            continue
        if source is not None and item.source != source:
            continue
        if evidence_type is not None and item.evidence_type != evidence_type:
            continue
        if tag is not None and tag not in item.tags:
            continue
        filtered.append(item)
    return filtered


def summarize_evidence(items: list[EvidenceItem]) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    targets: list[str] = []
    seen_targets: set[str] = set()
    for item in items or []:
        by_type[item.evidence_type] = by_type.get(item.evidence_type, 0) + 1
        by_source[item.source] = by_source.get(item.source, 0) + 1
        if item.target not in seen_targets:
            seen_targets.add(item.target)
            targets.append(item.target)
    return {"total": len(items or []), "by_type": by_type, "by_source": by_source, "targets": targets}
