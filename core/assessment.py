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
    created_at: str = field(default_factory=utc_now)
    approved_at: str | None = None

    def scope(self) -> Scope:
        return Scope(self.allowed_targets)

    def approve(self) -> "Assessment":
        self.approved = True
        self.approved_at = utc_now()
        return self

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "Assessment":
        return cls(
            name=str(data["name"]),
            allowed_targets=list(data["allowed_targets"]),  # type: ignore[arg-type]
            approved=bool(data.get("approved", False)),
            created_at=str(data.get("created_at") or utc_now()),
            approved_at=data.get("approved_at") if data.get("approved_at") else None,  # type: ignore[arg-type]
        )


def save_assessment(assessment: Assessment, path: str | Path) -> None:
    Path(path).write_text(json.dumps(assessment.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def load_assessment(path: str | Path) -> Assessment:
    return Assessment.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

