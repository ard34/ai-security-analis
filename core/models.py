from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from core.risk import normalize_severity


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


@dataclass(slots=True)
class Asset:
    value: str
    type: str = "unknown"
    id: str = field(default_factory=lambda: new_id("asset"))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Endpoint:
    path: str
    method: str = "GET"
    id: str = field(default_factory=lambda: new_id("endpoint"))
    url: str | None = None
    source: str = "local"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.method = self.method.upper()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Evidence:
    source: str
    content: str
    id: str = field(default_factory=lambda: new_id("evidence"))
    metadata: dict[str, Any] = field(default_factory=dict)
    collected_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    title: str
    severity: str = "info"
    description: str = ""
    id: str = field(default_factory=lambda: new_id("finding"))
    asset_id: str | None = None
    endpoint_id: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    is_potential: bool = True
    confidence: str = "low"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.is_potential = True

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["is_potential"] = True
        return data


@dataclass(slots=True)
class ScanResult:
    target: str
    workflow: str
    id: str = field(default_factory=lambda: new_id("scan"))
    assets: list[Asset] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    audit_events: list[dict[str, Any]] = field(default_factory=list)

    def complete(self) -> "ScanResult":
        self.completed_at = utc_now()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "workflow": self.workflow,
            "assets": [item.to_dict() for item in self.assets],
            "endpoints": [item.to_dict() for item in self.endpoints],
            "findings": [item.to_dict() for item in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "recommendations": list(self.recommendations),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "metadata": dict(self.metadata),
            "audit_events": list(self.audit_events),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanResult":
        result = cls(target=data["target"], workflow=data["workflow"], id=data.get("id", new_id("scan")))
        result.assets = [Asset(**item) for item in data.get("assets", [])]
        result.endpoints = [Endpoint(**item) for item in data.get("endpoints", [])]
        result.findings = [Finding(**item) for item in data.get("findings", [])]
        result.evidence = [Evidence(**item) for item in data.get("evidence", [])]
        result.recommendations = list(data.get("recommendations", []))
        result.started_at = data.get("started_at", result.started_at)
        result.completed_at = data.get("completed_at")
        result.metadata = dict(data.get("metadata", {}))
        result.audit_events = list(data.get("audit_events", []))
        return result

