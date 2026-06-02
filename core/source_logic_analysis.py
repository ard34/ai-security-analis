from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.evidence import read_text_limited
from core.manual_validation import attach_manual_validation_plan
from core.models import Finding
from modules.source_logic_analyzer import analyze_source_text
from modules.source_mapper import SOURCE_EXTENSIONS


@dataclass(slots=True)
class SourceLogicAnalysisResult:
    root: str
    findings: list[Finding]

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def analyze_source_logic(root: str | Path, *, max_file_bytes: int = 1_000_000) -> SourceLogicAnalysisResult:
    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise ValueError("source path must be a local directory")

    findings: list[Finding] = []
    for path in root_path.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if path.stat().st_size > max_file_bytes:
            continue
        rel = str(path.relative_to(root_path))
        text = read_text_limited(path, max_bytes=max_file_bytes)
        findings.extend(analyze_source_text(text, file_path=rel))

    for finding in findings:
        attach_manual_validation_plan(finding)
    return SourceLogicAnalysisResult(root=str(root_path), findings=findings)
