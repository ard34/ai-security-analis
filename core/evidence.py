from __future__ import annotations

from pathlib import Path
from typing import Any

from core.models import Evidence
from core.policies import redact_value


def collect_local_evidence(source: str, content: str, metadata: dict[str, Any] | None = None) -> Evidence:
    return Evidence(source=source, content=str(redact_value("content", content)), metadata=metadata or {})


def read_text_limited(path: str | Path, *, max_bytes: int) -> str:
    file_path = Path(path)
    size = file_path.stat().st_size
    if size > max_bytes:
        with file_path.open("rb") as handle:
            data = handle.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    return file_path.read_text(encoding="utf-8", errors="replace")


def redact_evidence(evidence: Evidence) -> Evidence:
    return Evidence(
        id=evidence.id,
        source=evidence.source,
        content=str(redact_value("content", evidence.content)),
        metadata=evidence.metadata,
        collected_at=evidence.collected_at,
    )

