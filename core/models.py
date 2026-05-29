from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_CONFIDENCES = {"low", "medium", "high"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_choice(value: str, allowed: set[str], field_name: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in allowed:
        raise ValueError(f"Invalid {field_name}: {value}")
    return normalized


@dataclass(frozen=True)
class Target:
    raw_input: str
    normalized_target: str
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Asset:
    value: str
    asset_type: str
    source: str


@dataclass(frozen=True)
class Endpoint:
    url: str
    method: str = "GET"
    path: str = "/"
    source: str = "unknown"


@dataclass
class Finding:
    target: str
    asset: str
    endpoint: str
    module: str
    finding_type: str
    title: str
    severity: str
    confidence: str
    evidence: str
    recommendation: str
    source: str
    is_potential: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = _normalize_choice(self.severity, VALID_SEVERITIES, "severity")
        self.confidence = _normalize_choice(self.confidence, VALID_CONFIDENCES, "confidence")
        self.is_potential = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "asset": self.asset,
            "endpoint": self.endpoint,
            "module": self.module,
            "finding_type": self.finding_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "source": self.source,
            "is_potential": self.is_potential,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    status: str
    result_count: int = 0
    commands_executed: list[list[str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class ScanSession:
    target: Target
    scan_mode: str
    status: str = "pending"
    allowed_scope: dict[str, Any] = field(default_factory=dict)
    assets: list[Asset] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)
    audit_log: dict[str, Any] = field(default_factory=dict)
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=_utc_now)
    ended_at: str | None = None

    def finish(self) -> None:
        self.ended_at = _utc_now()


@dataclass(frozen=True)
class ReportMetadata:
    project_name: str
    scan_id: str
    generated_at: str = field(default_factory=_utc_now)
    disclaimer: str = "Findings are potential findings and require manual validation."
