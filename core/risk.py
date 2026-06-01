from __future__ import annotations

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
_ALIASES = {
    "informational": "info",
    "none": "info",
    "unknown": "info",
    "moderate": "medium",
    "med": "medium",
    "severe": "high",
    "crit": "critical",
}


def normalize_severity(value: str | None) -> str:
    if not value:
        return "info"
    cleaned = str(value).strip().lower()
    cleaned = _ALIASES.get(cleaned, cleaned)
    return cleaned if cleaned in SEVERITY_ORDER else "info"


def severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.index(normalize_severity(value))


def max_severity(values: list[str]) -> str:
    if not values:
        return "info"
    return max((normalize_severity(v) for v in values), key=severity_rank)

