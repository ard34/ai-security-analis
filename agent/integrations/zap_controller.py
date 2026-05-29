from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

import requests

from agent.report.json_writer import write_json
from agent.utils.command_runner import command_exists


STATUS_PATH = "outputs/zap/zap_status.json"


def get_zap_settings(config: dict[str, Any]) -> dict[str, Any]:
    zap_cfg = config.get("zap", {}) if isinstance(config.get("zap"), dict) else {}
    host = str(zap_cfg.get("host", "127.0.0.1"))
    port = int(zap_cfg.get("port", 8090))
    api_url = str(zap_cfg.get("api_url", f"http://{host}:{port}")).rstrip("/")
    proxy_url = str(zap_cfg.get("proxy_url", f"http://{host}:{port}")).rstrip("/")
    return {
        "host": host,
        "port": port,
        "api_url": api_url,
        "proxy_url": proxy_url,
        "use_api_key": bool(zap_cfg.get("use_api_key", False)),
        "api_key": str(zap_cfg.get("api_key", "")),
        "auto_start": bool(zap_cfg.get("auto_start", True)),
        "enabled": bool(zap_cfg.get("enabled", True)),
    }


def zap_client(config: dict[str, Any]):
    from zapv2 import ZAPv2

    settings = get_zap_settings(config)
    proxies = {"http": settings["proxy_url"], "https": settings["proxy_url"]}
    if settings["use_api_key"]:
        return ZAPv2(apikey=settings["api_key"], proxies=proxies)
    return ZAPv2(proxies=proxies)


def _status_payload(config: dict[str, Any], status: str, message: str = "", version: str = "", started_by_agent: bool = False) -> dict[str, Any]:
    settings = get_zap_settings(config)
    payload = {
        "enabled": settings["enabled"],
        "status": status,
        "api_url": settings["api_url"],
        "proxy_url": settings["proxy_url"],
        "version": version,
        "started_by_agent": started_by_agent,
        "message": message,
    }
    write_json(STATUS_PATH, payload)
    return payload


def is_zap_alive(config: dict[str, Any]) -> bool:
    settings = get_zap_settings(config)
    if not settings["enabled"]:
        return False
    try:
        response = requests.get(f"{settings['api_url']}/JSON/core/view/version/", timeout=3)
        return response.ok
    except requests.RequestException:
        pass
    try:
        _ = zap_client(config).core.version
        return True
    except Exception:
        return False


def find_zap_command() -> str | None:
    for command in ["zaproxy", "zap.sh"]:
        if command_exists(command):
            return command
    fallback = Path("/usr/share/zaproxy/zap.sh")
    if fallback.exists():
        return str(fallback)
    return None


def start_zap_daemon(config: dict[str, Any]) -> dict[str, Any]:
    settings = get_zap_settings(config)
    command = find_zap_command()
    if not command:
        return _status_payload(config, "Not Installed", "OWASP ZAP command not found.")
    Path("logs").mkdir(parents=True, exist_ok=True)
    Path("outputs/zap").mkdir(parents=True, exist_ok=True)
    log_handle = Path("logs/zap_daemon.log").open("ab")
    args = [
        command,
        "-daemon",
        "-host",
        settings["host"],
        "-port",
        str(settings["port"]),
        "-config",
        "api.disablekey=true" if not settings["use_api_key"] else "api.disablekey=false",
    ]
    try:
        subprocess.Popen(args, stdout=log_handle, stderr=subprocess.STDOUT, close_fds=True)
    except Exception as exc:
        return _status_payload(config, "Failed", str(exc))
    return _status_payload(config, "Starting", "ZAP daemon started by agent.", started_by_agent=True)


def wait_for_zap(config: dict[str, Any], timeout_seconds: int = 60) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error = ""
    while time.monotonic() < deadline:
        try:
            client = zap_client(config)
            version = str(client.core.version)
            return _status_payload(config, "Ready", "ZAP API is ready.", version=version)
        except Exception as exc:
            last_error = str(exc)[:300]
            time.sleep(2)
    return _status_payload(config, "Failed", f"Timed out waiting for ZAP API. {last_error}")


def ensure_zap_running(config: dict[str, Any]) -> dict[str, Any]:
    settings = get_zap_settings(config)
    Path("outputs/zap").mkdir(parents=True, exist_ok=True)
    if not settings["enabled"]:
        return _status_payload(config, "Disabled", "ZAP integration disabled.")
    try:
        client = zap_client(config)
        version = str(client.core.version)
        return _status_payload(config, "Ready", "ZAP API is ready.", version=version)
    except Exception:
        pass
    if not settings["auto_start"]:
        return _status_payload(config, "Failed", "ZAP is not running and auto_start is disabled.")
    started = start_zap_daemon(config)
    if started["status"] == "Not Installed":
        return started
    if started["status"] == "Failed":
        return started
    waited = wait_for_zap(config, timeout_seconds=int(settings.get("startup_timeout_seconds", 60) or 60))
    waited["started_by_agent"] = True
    write_json(STATUS_PATH, waited)
    return waited
