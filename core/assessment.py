from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from core.logging import redact_sensitive_data


VALID_ENVIRONMENTS = {"local", "dev", "staging", "preprod", "production"}
VALID_ASSESSMENT_STATUSES = {"draft", "approved", "in_progress", "completed", "archived"}
VALID_SCAN_MODES = {"strict", "safe", "standard"}
SENSITIVE_TERMS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization: bearer",
    "cookie",
    "set-cookie",
    "credential",
    "private_key",
}


@dataclass(frozen=True)
class AssessmentScope:
    allowed_domains: list[str]
    allowed_ips: list[str] = field(default_factory=list)
    denied_patterns: list[str] = field(default_factory=list)
    environment: str = "staging"

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_domains", _normalize_domains(self.allowed_domains))
        object.__setattr__(self, "allowed_ips", [str(item).strip() for item in self.allowed_ips or [] if str(item).strip()])
        object.__setattr__(
            self,
            "denied_patterns",
            [str(item).strip() for item in self.denied_patterns or [] if str(item).strip()],
        )
        object.__setattr__(self, "environment", str(self.environment or "").strip().lower())


@dataclass(frozen=True)
class AssessmentMetadata:
    assessment_id: str
    name: str
    owner: str
    operator: str
    authorization_note: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AssessmentProject:
    metadata: AssessmentMetadata
    scope: AssessmentScope
    scan_mode: str = "safe"
    status: str = "draft"
    tags: list[str] = field(default_factory=list)
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "scan_mode", str(self.scan_mode or "").strip().lower())
        object.__setattr__(self, "status", str(self.status or "").strip().lower())
        object.__setattr__(self, "tags", [str(item).strip() for item in self.tags or [] if str(item).strip()])


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_domains(domains: list[str] | None) -> list[str]:
    return [str(domain).strip().lower() for domain in domains or [] if str(domain).strip()]


def _require_non_empty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Assessment {field_name} must be a non-empty string.")


def _contains_sensitive_text(value: object) -> bool:
    if isinstance(value, dict):
        return any(_contains_sensitive_text(key) or _contains_sensitive_text(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_sensitive_text(item) for item in value)
    text = str(value or "").lower()
    return any(term in text for term in SENSITIVE_TERMS)


def _assert_no_sensitive_data(value: object, field_name: str) -> None:
    if _contains_sensitive_text(value):
        raise ValueError(f"Assessment {field_name} must not contain sensitive data.")
    if redact_sensitive_data(value) != value:
        raise ValueError(f"Assessment {field_name} must not contain sensitive data.")


def create_assessment_project(
    name: str,
    owner: str,
    operator: str,
    authorization_note: str,
    allowed_domains: list[str],
    allowed_ips: list[str] | None = None,
    denied_patterns: list[str] | None = None,
    environment: str = "staging",
    scan_mode: str = "safe",
    tags: list[str] | None = None,
    notes: str = "",
) -> AssessmentProject:
    now = _utc_now()
    project = AssessmentProject(
        metadata=AssessmentMetadata(
            assessment_id=str(uuid4()),
            name=str(name or "").strip(),
            owner=str(owner or "").strip(),
            operator=str(operator or "").strip(),
            authorization_note=str(authorization_note or "").strip(),
            created_at=now,
            updated_at=now,
        ),
        scope=AssessmentScope(
            allowed_domains=allowed_domains,
            allowed_ips=allowed_ips or [],
            denied_patterns=denied_patterns or [],
            environment=environment,
        ),
        scan_mode=scan_mode,
        status="draft",
        tags=tags or [],
        notes=str(notes or ""),
    )
    validate_assessment_project(project)
    return project


def validate_assessment_project(project: AssessmentProject) -> None:
    if not isinstance(project, AssessmentProject):
        raise ValueError("project must be an AssessmentProject.")
    _require_non_empty(project.metadata.assessment_id, "assessment_id")
    _require_non_empty(project.metadata.name, "name")
    _require_non_empty(project.metadata.owner, "owner")
    _require_non_empty(project.metadata.operator, "operator")
    _require_non_empty(project.metadata.authorization_note, "authorization_note")
    if not project.scope.allowed_domains and not project.scope.allowed_ips:
        raise ValueError("Assessment must include at least one allowed domain or allowed IP.")
    if project.scope.environment not in VALID_ENVIRONMENTS:
        raise ValueError(f"Invalid assessment environment: {project.scope.environment}")
    if project.scan_mode not in VALID_SCAN_MODES:
        raise ValueError(f"Invalid assessment scan mode: {project.scan_mode}")
    if project.status not in VALID_ASSESSMENT_STATUSES:
        raise ValueError(f"Invalid assessment status: {project.status}")
    if project.scope.allowed_domains != _normalize_domains(project.scope.allowed_domains):
        raise ValueError("Assessment allowed domains must be normalized lowercase.")
    _assert_no_sensitive_data(project.metadata.authorization_note, "authorization_note")
    _assert_no_sensitive_data(project.metadata.name, "metadata")
    _assert_no_sensitive_data(project.metadata.owner, "metadata")
    _assert_no_sensitive_data(project.metadata.operator, "metadata")
    _assert_no_sensitive_data(project.tags, "tags")
    _assert_no_sensitive_data(project.notes, "notes")


def assessment_project_to_dict(project: AssessmentProject) -> dict[str, Any]:
    validate_assessment_project(project)
    return redact_sensitive_data(asdict(project))


def assessment_project_from_dict(data: dict[str, Any]) -> AssessmentProject:
    if not isinstance(data, dict):
        raise ValueError("assessment project data must be a dict.")
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    scope = data.get("scope") if isinstance(data.get("scope"), dict) else {}
    project = AssessmentProject(
        metadata=AssessmentMetadata(
            assessment_id=str(metadata.get("assessment_id") or ""),
            name=str(metadata.get("name") or ""),
            owner=str(metadata.get("owner") or ""),
            operator=str(metadata.get("operator") or ""),
            authorization_note=str(metadata.get("authorization_note") or ""),
            created_at=str(metadata.get("created_at") or ""),
            updated_at=str(metadata.get("updated_at") or ""),
        ),
        scope=AssessmentScope(
            allowed_domains=list(scope.get("allowed_domains") or []),
            allowed_ips=list(scope.get("allowed_ips") or []),
            denied_patterns=list(scope.get("denied_patterns") or []),
            environment=str(scope.get("environment") or "staging"),
        ),
        scan_mode=str(data.get("scan_mode") or "safe"),
        status=str(data.get("status") or "draft"),
        tags=list(data.get("tags") or []),
        notes=str(data.get("notes") or ""),
    )
    validate_assessment_project(project)
    return project


def is_assessment_approved(project: AssessmentProject) -> bool:
    validate_assessment_project(project)
    return project.status == "approved"


def approve_assessment_project(project: AssessmentProject) -> AssessmentProject:
    validate_assessment_project(project)
    updated = replace(project, status="approved", metadata=replace(project.metadata, updated_at=_utc_now()))
    validate_assessment_project(updated)
    return updated


def archive_assessment_project(project: AssessmentProject) -> AssessmentProject:
    validate_assessment_project(project)
    updated = replace(project, status="archived", metadata=replace(project.metadata, updated_at=_utc_now()))
    validate_assessment_project(updated)
    return updated
