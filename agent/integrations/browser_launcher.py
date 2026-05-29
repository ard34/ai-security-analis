from __future__ import annotations

import os
import shutil
import subprocess


AUTH_MESSAGE = """[AUTH FLOW DETECTED]
Login/register endpoint ditemukan.
Browser akan dibuka melalui Burp proxy.
Silakan login/register manual, klik menu penting, lalu export HTTP history dari Burp ke tmp/burp_history.har."""


def launch_browser(url: str, config: dict[str, object]) -> None:
    proxy = config.get("proxy", {}) if isinstance(config.get("proxy"), dict) else {}
    browser = config.get("browser", {}) if isinstance(config.get("browser"), dict) else {}
    host = proxy.get("host", "127.0.0.1")
    port = proxy.get("port", 8080)
    chromium = str(browser.get("chromium_path", "chromium"))
    profile = str(browser.get("user_data_dir", "")) or os.path.join(os.path.expanduser("~"), ".config", "ai-security-analyst", "chromium-profile")
    command = [chromium, f"--proxy-server=http://{host}:{port}", f"--user-data-dir={profile}", url]

    print(AUTH_MESSAGE)
    if not shutil.which(chromium):
        print("[!] Chromium not found. Run manually:")
        print(" ".join(command))
        return
    os.makedirs(profile, exist_ok=True)
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
