from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from core.evidence import read_text_limited

ROUTE_PATTERNS = [
    re.compile(r"@(?:app|router)\.(get|post|put|patch|delete)\(['\"]([^'\"]+)['\"]"),
    re.compile(r"(?:app|router)\.(get|post|put|patch|delete)\(['\"]([^'\"]+)['\"]"),
    re.compile(r"Route::(get|post|put|patch|delete)\(['\"]([^'\"]+)['\"]"),
]
CONFIG_HINTS = ("SECRET_KEY", "DEBUG", "CORS", "ALLOWED_HOSTS", "DATABASE_URL", "JWT", "SESSION")
AUTH_HINTS = ("login", "logout", "auth", "permission", "role", "middleware", "csrf")
SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".php", ".rb", ".go", ".java", ".kt", ".cs"}


@dataclass(slots=True)
class SourceMap:
    root: str
    files_scanned: int = 0
    skipped_large_files: int = 0
    languages: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
    routes: list[dict[str, str]] = field(default_factory=list)
    config_hints: list[dict[str, str]] = field(default_factory=list)
    auth_hints: list[dict[str, str]] = field(default_factory=list)
    security_smells: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "skipped_large_files": self.skipped_large_files,
            "languages": sorted(self.languages),
            "frameworks": sorted(self.frameworks),
            "routes": self.routes,
            "config_hints": self.config_hints,
            "auth_hints": self.auth_hints,
            "security_smells": self.security_smells,
        }


def _language_for(path: Path) -> str | None:
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".jsx": "javascript",
        ".php": "php",
        ".rb": "ruby",
        ".go": "go",
        ".java": "java",
        ".cs": "csharp",
    }.get(path.suffix.lower())


def _framework_hints(text: str) -> set[str]:
    hints: set[str] = set()
    checks = {"fastapi": "FastAPI", "flask": "Flask", "express": "Express", "django": "Django", "laravel": "Laravel"}
    lowered = text.lower()
    for needle, name in checks.items():
        if needle in lowered:
            hints.add(name)
    return hints


def map_source_folder(root: str | Path, *, max_file_bytes: int = 1_000_000) -> SourceMap:
    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        raise ValueError("source path must be a local directory")
    result = SourceMap(root=str(root_path))
    for path in root_path.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if path.stat().st_size > max_file_bytes:
            result.skipped_large_files += 1
            continue
        rel = str(path.relative_to(root_path))
        text = read_text_limited(path, max_bytes=max_file_bytes)
        result.files_scanned += 1
        language = _language_for(path)
        if language:
            result.languages.add(language)
        result.frameworks.update(_framework_hints(text))
        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(text):
                method, route = match.group(1), match.group(2)
                result.routes.append({"method": method.upper(), "path": route, "file": rel})
        for hint in CONFIG_HINTS:
            if hint.lower() in text.lower():
                result.config_hints.append({"hint": hint, "file": rel})
        for hint in AUTH_HINTS:
            if hint.lower() in text.lower():
                result.auth_hints.append({"hint": hint, "file": rel})
        for smell in ("DEBUG = True", "verify=False", "SECRET_KEY = \"\"", "CORS_ALLOW_ALL_ORIGINS = True"):
            if smell.lower() in text.lower():
                result.security_smells.append({"smell": smell, "file": rel})
    return result

