from __future__ import annotations

from pathlib import Path
from typing import Any

from agent.report.json_writer import read_json, write_json

STATE_PATH = Path("outputs/auth_crawl_state.json")

DEFAULT_STATE: dict[str, object] = {
    "auth_endpoint_detected": False,
    "burp_proxy_ready": False,
    "browser_opened": False,
    "waiting_for_manual_login": False,
    "manual_login_completed": False,
    "authenticated_crawl_completed": False,
    "har_path": "tmp/authenticated_session.har",
}


def get_state() -> dict[str, object]:
    state = dict(DEFAULT_STATE)
    existing = read_json(STATE_PATH, default={}) or {}
    if isinstance(existing, dict):
        state.update(existing)
    return state


def set_state(key: str, value: Any) -> dict[str, object]:
    if key not in DEFAULT_STATE:
        raise KeyError(f"Unknown auth crawl state key: {key}")
    state = get_state()
    state[key] = value
    write_json(STATE_PATH, state)
    return state


def reset_state() -> dict[str, object]:
    state = dict(DEFAULT_STATE)
    write_json(STATE_PATH, state)
    return state
