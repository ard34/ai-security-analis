from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ui.app import safe_table


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    rows = safe_table([{"assets": [{"hostname": "a.example.com"}], "endpoints": ["https://a.example.com/login"]}])
    check(isinstance(rows[0]["assets"], str), "nested assets converted")
    check(isinstance(rows[0]["endpoints"], str), "nested endpoints converted")
    print("dashboard_safe_render_helpers tests passed")


if __name__ == "__main__":
    main()
