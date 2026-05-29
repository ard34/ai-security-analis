from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.integrations.zap_controller import ensure_zap_running, get_zap_settings
from agent.report.json_writer import read_json


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    settings = get_zap_settings({})
    check(settings["port"] == 8090, "default zap port")
    check(settings["api_url"] == "http://127.0.0.1:8090", "default api url")
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        fake = Mock()
        fake.core.version = "2.17.0"
        with patch("agent.integrations.zap_controller.zap_client", return_value=fake):
            status = ensure_zap_running({})
        check(status["status"] == "Ready", "ready status")
        written = read_json("outputs/zap/zap_status.json", default={})
        check(written["version"] == "2.17.0", "status file version")
        disabled = ensure_zap_running({"zap": {"enabled": False}})
        check(disabled["status"] == "Disabled", "disabled status")
    print("zap_controller_status tests passed")


if __name__ == "__main__":
    main()
