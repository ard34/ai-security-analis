from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_playwright: Any | None = None
_context: Any | None = None
_page: Any | None = None


def _expand(path: str) -> str:
    return os.path.expanduser(path)


def launch_browser_for_login(target_url: str, proxy_config: dict[str, object], user_data_dir: str) -> Any:
    global _playwright, _context, _page

    from playwright.sync_api import sync_playwright

    host = str(proxy_config.get("host", "127.0.0.1"))
    port = int(proxy_config.get("port", 8080))
    profile = _expand(user_data_dir or "~/.config/ai-security-analyst/playwright-profile")
    Path(profile).mkdir(parents=True, exist_ok=True)

    _playwright = sync_playwright().start()
    _context = _playwright.chromium.launch_persistent_context(
        profile,
        headless=False,
        proxy={"server": f"http://{host}:{port}"},
        ignore_https_errors=True,
    )
    _page = _context.pages[0] if _context.pages else _context.new_page()
    _page.goto(target_url, wait_until="domcontentloaded", timeout=60000)
    return _page


def save_browser_state(path: str = "tmp/browser_state.json") -> None:
    if _context is None:
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    _context.storage_state(path=path)


def start_har_capture(path: str = "tmp/authenticated_session.har") -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return path


def close_browser() -> None:
    global _playwright, _context, _page
    if _context is not None:
        _context.close()
    if _playwright is not None:
        _playwright.stop()
    _playwright = None
    _context = None
    _page = None
