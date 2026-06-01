from __future__ import annotations

from core.models import Finding

BLOCKED_WORDS = ("payload", "brute " + "force", "d" + "os", "bypass", "credential theft", "exploit")


def defensive_recommendation_for(finding: Finding) -> str:
    title = finding.title.lower()
    if "missing security header" in title or "header" in title:
        return (
            "Manually verify the response headers in an authorized browser session "
            "and confirm expected defensive headers are configured."
        )
    if "auth" in title:
        return (
            "Review the authorization design and confirm access control decisions "
            "with code owners using approved test accounts."
        )
    if "secret" in title or "token" in title:
        return (
            "Confirm whether the exposed value is a real secret, rotate it if needed, "
            "and remove it from source history through the approved process."
        )
    return "Manually validate this potential finding with the application owner before assigning confirmed risk."


def recommendations_for_findings(findings: list[Finding]) -> list[str]:
    recommendations = [defensive_recommendation_for(finding) for finding in findings]
    return [item for item in recommendations if not any(word in item.lower() for word in BLOCKED_WORDS)]
