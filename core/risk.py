from __future__ import annotations


SEVERITY_SCORE = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

CONFIDENCE_WEIGHT = {
    "low": 0,
    "medium": 1,
    "high": 2,
}


def normalize_severity(severity: str) -> str:
    normalized = str(severity or "").strip().lower()
    if normalized not in SEVERITY_SCORE:
        raise ValueError(f"Invalid severity: {severity}")
    return normalized


def normalize_confidence(confidence: str) -> str:
    normalized = str(confidence or "").strip().lower()
    if normalized not in CONFIDENCE_WEIGHT:
        raise ValueError(f"Invalid confidence: {confidence}")
    return normalized


def severity_to_score(severity: str) -> int:
    return SEVERITY_SCORE[normalize_severity(severity)]


def cap_passive_severity(severity: str, strong_evidence: bool = False) -> str:
    normalized = normalize_severity(severity)
    if strong_evidence:
        return normalized
    return "medium" if SEVERITY_SCORE[normalized] > SEVERITY_SCORE["medium"] else normalized


def calculate_priority(severity: str, confidence: str, passive: bool = True, strong_evidence: bool = False) -> int:
    sev = cap_passive_severity(severity, strong_evidence=strong_evidence) if passive else normalize_severity(severity)
    conf = normalize_confidence(confidence)
    return SEVERITY_SCORE[sev] * 10 + CONFIDENCE_WEIGHT[conf]


def priority_score(severity: str, confidence: str, passive: bool = True, strong_evidence: bool = False) -> int:
    return calculate_priority(severity, confidence, passive=passive, strong_evidence=strong_evidence)


def validate_finding_risk(severity: str, confidence: str, passive: bool = True, strong_evidence: bool = False) -> dict[str, int | str | bool]:
    normalized_severity = cap_passive_severity(severity, strong_evidence=strong_evidence) if passive else normalize_severity(severity)
    normalized_confidence = normalize_confidence(confidence)
    return {
        "severity": normalized_severity,
        "confidence": normalized_confidence,
        "passive": passive,
        "priority": calculate_priority(normalized_severity, normalized_confidence, passive=False),
    }
