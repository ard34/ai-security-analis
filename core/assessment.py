from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.models import utc_now
from core.scope import Scope


@dataclass(slots=True)
class Assessment:
    name: str
    allowed_targets: list[str]
    approved: bool = False
    status: str = "draft"
    owner_operator: str = ""
    authorization_note: str = ""
    environment: str = "pre-production"
    allowed_ips: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    approved_at: str | None = None
    archived_at: str | None = None

    def scope(self) -> Scope:
        return Scope([*self.allowed_targets, *self.allowed_ips])

    def approve(self) -> "Assessment":
        self.approved = True
        self.status = "approved"
        self.approved_at = utc_now()
        return self

    def archive(self) -> "Assessment":
        self.approved = False
        self.status = "archived"
        self.archived_at = utc_now()
        return self

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "Assessment":
        return cls(
            name=str(data["name"]),
            allowed_targets=list(data["allowed_targets"]),  # type: ignore[arg-type]
            approved=bool(data.get("approved", False)),
            status=str(data.get("status") or ("approved" if data.get("approved", False) else "draft")),
            owner_operator=str(data.get("owner_operator") or data.get("owner") or ""),
            authorization_note=str(data.get("authorization_note") or data.get("authorization") or data.get("note") or ""),
            environment=str(data.get("environment") or "pre-production"),
            allowed_ips=list(data.get("allowed_ips", [])),  # type: ignore[arg-type]
            created_at=str(data.get("created_at") or utc_now()),
            approved_at=data.get("approved_at") if data.get("approved_at") else None,  # type: ignore[arg-type]
            archived_at=data.get("archived_at") if data.get("archived_at") else None,  # type: ignore[arg-type]
        )


def save_assessment(assessment: Assessment, path: str | Path) -> None:
    Path(path).write_text(json.dumps(assessment.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def load_assessment(path: str | Path) -> Assessment:
    return Assessment.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
