from __future__ import annotations

from agent.report.json_writer import read_json, write_json

AUTH_PATTERNS = [
    "/login",
    "/signin",
    "/auth/login",
    "/register",
    "/signup",
    "/create-account",
    "/forgot-password",
    "/reset-password",
    "/oauth",
    "/sso",
]


def detect_auth_endpoints(endpoints_path: str = "outputs/endpoints.json") -> list[str]:
    endpoints = read_json(endpoints_path, default=[]) or []
    matches = [
        url
        for url in endpoints
        if any(pattern in url.lower() for pattern in AUTH_PATTERNS)
    ]
    write_json("outputs/auth_endpoints.json", matches)
    return matches
