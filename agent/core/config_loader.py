from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def load_config(config_path: str | Path) -> dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Config path is not a file: {path}")

    with path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    user_data_dir = config.setdefault("browser", {}).get("user_data_dir", "")
    if not user_data_dir:
        config["browser"]["user_data_dir"] = os.path.join(
            os.path.expanduser("~"), ".config", "ai-security-analyst", "playwright-profile"
        )
    return config
