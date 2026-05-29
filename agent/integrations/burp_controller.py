from __future__ import annotations

import shutil
import socket
import subprocess
import time

MANUAL_BURP_MESSAGE = "Please open Burp Suite manually and ensure proxy listener is running on 127.0.0.1:8080"


def is_proxy_alive(host: str = "127.0.0.1", port: int = 8080) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return True
    except OSError:
        return False


def launch_burp() -> subprocess.Popen[bytes] | None:
    command = "burpsuite"
    if not shutil.which(command):
        print(MANUAL_BURP_MESSAGE)
        return None
    try:
        return subprocess.Popen([command], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        print(MANUAL_BURP_MESSAGE)
        return None


def ensure_burp_running(config: dict[str, object]) -> bool:
    proxy = config.get("proxy", {}) if isinstance(config.get("proxy"), dict) else {}
    host = str(proxy.get("host", "127.0.0.1"))
    port = int(proxy.get("port", 8080))
    if is_proxy_alive(host, port):
        return True

    launch_burp()
    for _ in range(10):
        time.sleep(1)
        if is_proxy_alive(host, port):
            return True

    print(f"Please open Burp Suite manually and ensure proxy listener is running on {host}:{port}")
    return False
